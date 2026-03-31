/* ==========================================================================
 * rdma_fabric.c - RDMA transport layer using libfabric (OFI).
 * --------------------------------------------------------------------------
 * Based on rdma.c by zhenwei pi <pizhenwei@bytedance.com>
 * Adapted to use libfabric instead of ibverbs/rdma_cm.
 *
 * Copyright (C) 2021-2024  zhenwei pi <pizhenwei@bytedance.com>
 *
 * This work is licensed under BSD 3-Clause, License 1 of the COPYING file in
 * the top-level directory.
 * ==========================================================================
 */
/*
 * Copyright (c) Valkey Contributors
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#define VALKEYMODULE_CORE_MODULE
#include "server.h" // Include server.h to use serverLog.
#include "serverassert.h"
#include "connection.h"

#if defined __linux__ && defined USE_RDMA /* currently RDMA is only supported on Linux */
#if (USE_RDMA == 1 /* BUILD_YES */) || \
    ((USE_RDMA == 2 /* BUILD_MODULE */) && defined(BUILD_RDMA_MODULE) && (BUILD_RDMA_MODULE == 2))
#include "connhelpers.h"

#include <arpa/inet.h>
#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>
#include <rdma/fi_rma.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/mman.h>

typedef struct ValkeyRdmaFeature {
    /* defined as following Opcodes */
    uint16_t opcode;
    /* select features */
    uint16_t select;
    uint8_t rsvd[20];
    /* feature bits */
    uint64_t features;
} ValkeyRdmaFeature;

typedef struct ValkeyRdmaKeepalive {
    /* defined as following Opcodes */
    uint16_t opcode;
    uint8_t rsvd[30];
} ValkeyRdmaKeepalive;

typedef struct ValkeyRdmaMemory {
    /* defined as following Opcodes */
    uint16_t opcode;
    uint8_t rsvd[14];
    /* address of a transfer buffer which is used to receive remote streaming data,
     * aka 'RX buffer address'. The remote side should use this as 'TX buffer address' */
    uint64_t addr;
    /* length of the 'RX buffer' */
    uint32_t length;
    /* the RDMA remote key of 'RX buffer' */
    uint32_t key;
} ValkeyRdmaMemory;

typedef union ValkeyRdmaCmd {
    ValkeyRdmaFeature feature;
    ValkeyRdmaKeepalive keepalive;
    ValkeyRdmaMemory memory;
} ValkeyRdmaCmd;

typedef enum ValkeyRdmaOpcode {
    GetServerFeature = 0,
    SetClientFeature = 1,
    Keepalive = 2,
    RegisterXferMemory = 3,
} ValkeyRdmaOpcode;

#define VALKEY_BUILD_BUG_ON(cond) ((void)sizeof(char[1 - 2 * !!(cond)]))
#define VALKEY_RDMA_MAX_WQE 1024
#define VALKEY_RDMA_DEFAULT_RX_SIZE (1024 * 1024)
#define VALKEY_RDMA_MIN_RX_SIZE (64 * 1024)
#define VALKEY_RDMA_MAX_RX_SIZE (16 * 1024 * 1024)
#define VALKEY_RDMA_SYNCIO_RES 10
#define VALKEY_RDMA_INVALID_OPCODE 0xffff
#define VALKEY_RDMA_KEEPALIVE_MS 3000

#define RDMA_CONN_FLAG_POSTPONE_UPDATE_STATE (1 << 0)

typedef struct rdma_connection {
    connection c;
    struct fid_ep *ep;
    int flags;
    int last_errno;
    listNode *pending_list_node;
} rdma_connection;

typedef struct RdmaXfer {
    struct fid_mr *mr; /* memory region of the transfer buffer */
    void *mr_desc;     /* local MR descriptor for data ops */
    char *addr;        /* address of transfer buffer in local memory */
    uint32_t length;   /* bytes of transfer buffer */
    uint32_t offset;   /* the offset of consumed transfer buffer */
    uint32_t pos;      /* the position in use of the transfer buffer */
} RdmaXfer;

typedef struct RdmaContext {
    connection *conn;
    char *ip;
    int port;
    long long keepalive_te; /* RDMA has no transport layer keepalive */
    struct fi_info *fi;
    struct fid_fabric *fabric;
    struct fid_domain *domain;
    struct fid_eq *eq;
    struct fid_cq *cq;
    int cq_fd;              /* CQ wait fd (replaces comp_channel) */

    /* TX */
    RdmaXfer tx;
    char *tx_addr;      /* remote transfer buffer address */
    uint64_t tx_key;    /* remote transfer buffer key */
    uint32_t tx_length; /* remote transfer buffer length */
    uint32_t tx_offset; /* remote transfer buffer offset */
    uint32_t tx_ops;    /* operations on remote transfer */

    /* RX */
    RdmaXfer rx;

    /* CMD 0 ~ VALKEY_RDMA_MAX_WQE for recv buffer
     * VALKEY_RDMA_MAX_WQE ~ 2 * VALKEY_RDMA_MAX_WQE -1 for send buffer */
    ValkeyRdmaCmd *cmd_buf;
    struct fid_mr *cmd_mr;
    void *cmd_mr_desc;  /* local MR descriptor for cmd ops */
} RdmaContext;

typedef struct rdma_listener {
    struct fid_pep *pep;
    struct fid_eq *eq;
    struct fid_fabric *fabric;
    struct fi_info *fi;
} rdma_listener;

/* RDMA connection is always writable, it has no POLLOUT event to drive the write handler, record available write
 * handler into pending list */
static list *pending_list;

static rdma_listener *rdma_listeners;
static serverRdmaContextConfig *rdma_config;

static size_t page_size;

static ConnectionType CT_RDMA;

static void serverRdmaError(char *err, const char *fmt, ...) {
    va_list ap;

    if (!err) return;
    va_start(ap, fmt);
    vsnprintf(err, ANET_ERR_LEN, fmt, ap);
    va_end(ap);
}

static inline int connRdmaAllowCommand(void) {
    /* RDMA MR is not accessible in a child process, avoid segment fault due to
     * invalid MR access, close it rather than server random crash */
    if (server.in_fork_child != CHILD_TYPE_NONE) {
        return C_ERR;
    }

    return C_OK;
}

static inline int connRdmaAllowRW(connection *conn) {
    if (conn->state == CONN_STATE_ERROR || conn->state == CONN_STATE_CLOSED) {
        return C_ERR;
    }

    return connRdmaAllowCommand();
}

static int rdmaPostRecv(RdmaContext *ctx, struct fid_ep *ep, ValkeyRdmaCmd *cmd) {
    struct iovec iov;
    size_t length = sizeof(ValkeyRdmaCmd);
    int ret;

    if (connRdmaAllowCommand()) {
        return C_ERR;
    }

    iov.iov_base = cmd;
    iov.iov_len = length;

    struct fi_msg msg = {
        .msg_iov = &iov,
        .desc = &ctx->cmd_mr_desc,
        .iov_count = 1,
        .addr = FI_ADDR_UNSPEC,
        .context = cmd,
    };

    ret = fi_recvmsg(ep, &msg, 0);
    if (ret && (ret != -FI_EAGAIN)) {
        serverLog(LL_WARNING, "RDMA: post recv failed: %d", ret);
        return C_ERR;
    }

    return C_OK;
}

/* To make Valkey forkable, buffer which is registered as RDMA memory region should be
 * aligned to page size. And the length  also need be aligned to page size.
 * Random segment-fault case like this:
 * 0x7f2764ac5000      -      0x7f2764ac7000
 * |ptr0 128| ... |ptr1 4096| ... |ptr2 512|
 *
 * After ibv_reg_mr(pd, ptr1, 4096, access), the full range of 8K  becomes DONTFORK. And
 * the child process will hit a segment fault during access ptr0/ptr2.
 *
 * The portable posix_memalign(&tmp, page_size, aligned_size) would be fine too. However,
 * RDMA is supported by Linux only, so it would not break anything. Using raw mmap syscall
 * to allocate a separate virtual memory area(VMA), also make it protected by the 2 guard
 * pages (a top one and a bottom one).
 */
static void *rdmaMemoryAlloc(size_t size) {
    size_t real_size, aligned_size = (size + page_size - 1) & (~(page_size - 1));
    uint8_t *ptr;

    real_size = aligned_size + 2 * page_size;
    ptr = mmap(NULL, real_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        serverPanic("failed to allocate memory for RDMA region");
    }

    madvise(ptr, real_size, MADV_DONTDUMP);                 /* no need to dump this VMA on coredump */
    mprotect(ptr, page_size, PROT_NONE);                    /* top page of this VMA */
    mprotect(ptr + size + page_size, page_size, PROT_NONE); /* bottom page of this VMA */

    return ptr + page_size;
}

static void rdmaMemoryFree(void *ptr, size_t size) {
    uint8_t *real_ptr;
    size_t real_size, aligned_size;

    if (!ptr) {
        return;
    }

    if ((unsigned long)ptr & (page_size - 1)) {
        serverPanic("unaligned memory in use for RDMA region");
    }

    aligned_size = (size + page_size - 1) & (~(page_size - 1));
    real_size = aligned_size + 2 * page_size;
    real_ptr = (uint8_t *)ptr - page_size;

    if (munmap(real_ptr, real_size)) {
        serverPanic("failed to free memory for RDMA region");
    }
}

static void rdmaDestroyIoBuf(RdmaContext *ctx) {
    if (ctx->rx.mr) {
        fi_close(&ctx->rx.mr->fid);
        ctx->rx.mr = NULL;
    }

    rdmaMemoryFree(ctx->rx.addr, ctx->rx.length);
    ctx->rx.addr = NULL;

    if (ctx->tx.mr) {
        fi_close(&ctx->tx.mr->fid);
        ctx->tx.mr = NULL;
    }

    rdmaMemoryFree(ctx->tx.addr, ctx->tx.length);
    ctx->tx.addr = NULL;

    if (ctx->cmd_mr) {
        fi_close(&ctx->cmd_mr->fid);
        ctx->cmd_mr = NULL;
    }

    rdmaMemoryFree(ctx->cmd_buf, sizeof(ValkeyRdmaCmd) * VALKEY_RDMA_MAX_WQE * 2);
    ctx->cmd_buf = NULL;
}

static int rdmaSetupIoBuf(RdmaContext *ctx, struct fid_ep *ep) {
    uint64_t access = FI_RECV | FI_SEND;
    size_t length = sizeof(ValkeyRdmaCmd) * VALKEY_RDMA_MAX_WQE * 2;
    ValkeyRdmaCmd *cmd;
    int i, ret;

    /* setup CMD buf & MR */
    ctx->cmd_buf = rdmaMemoryAlloc(length);
    ret = fi_mr_reg(ctx->domain, ctx->cmd_buf, length, access, 0, 0, 0, &ctx->cmd_mr, NULL);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: reg mr for CMD failed: %s", fi_strerror(-ret));
        goto destroy_iobuf;
    }
    ctx->cmd_mr_desc = fi_mr_desc(ctx->cmd_mr);

    for (i = 0; i < VALKEY_RDMA_MAX_WQE; i++) {
        cmd = ctx->cmd_buf + i;

        if (rdmaPostRecv(ctx, ep, cmd) == C_ERR) {
            serverLog(LL_WARNING, "RDMA: post recv failed");
            goto destroy_iobuf;
        }
    }

    for (i = VALKEY_RDMA_MAX_WQE; i < VALKEY_RDMA_MAX_WQE * 2; i++) {
        cmd = ctx->cmd_buf + i;
        cmd->keepalive.opcode = VALKEY_RDMA_INVALID_OPCODE;
    }

    /* setup recv buf & MR */
    access = FI_RECV | FI_SEND | FI_READ | FI_WRITE | FI_REMOTE_READ | FI_REMOTE_WRITE;
    length = rdma_config->rx_size;
    ctx->rx.addr = rdmaMemoryAlloc(length);
    ctx->rx.length = length;
    ret = fi_mr_reg(ctx->domain, ctx->rx.addr, length, access, 0, 0, 0, &ctx->rx.mr, NULL);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: reg mr for recv buffer failed: %s", fi_strerror(-ret));
        goto destroy_iobuf;
    }
    ctx->rx.mr_desc = fi_mr_desc(ctx->rx.mr);

    return C_OK;

destroy_iobuf:
    rdmaDestroyIoBuf(ctx);
    return C_ERR;
}

static int rdmaCreateResource(RdmaContext *ctx, struct fid_ep *ep) {
    struct fi_cq_attr cq_attr = {0};
    struct fid_cq *cq = NULL;
    int ret, fd;

    /* domain should already be set up before calling this */
    if (!ctx->domain) {
        serverLog(LL_WARNING, "RDMA: domain not initialized");
        return C_ERR;
    }

    /* Create CQ with FD wait for event-driven processing */
    cq_attr.size = VALKEY_RDMA_MAX_WQE * 2;
    cq_attr.format = FI_CQ_FORMAT_DATA;
    cq_attr.wait_obj = FI_WAIT_FD;
    ret = fi_cq_open(ctx->domain, &cq_attr, &cq, NULL);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: fi_cq_open failed: %s", fi_strerror(-ret));
        return C_ERR;
    }
    ctx->cq = cq;

    /* Get CQ fd for event loop */
    ret = fi_control(&cq->fid, FI_GETWAIT, &fd);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: fi_control FI_GETWAIT failed: %s", fi_strerror(-ret));
        return C_ERR;
    }
    ctx->cq_fd = fd;

    /* Bind CQ to endpoint */
    ret = fi_ep_bind(ep, &cq->fid, FI_TRANSMIT | FI_RECV);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: fi_ep_bind CQ failed: %s", fi_strerror(-ret));
        return C_ERR;
    }

    /* Bind EQ to endpoint */
    if (ctx->eq) {
        ret = fi_ep_bind(ep, &ctx->eq->fid, 0);
        if (ret) {
            serverLog(LL_WARNING, "RDMA: fi_ep_bind EQ failed: %s", fi_strerror(-ret));
            return C_ERR;
        }
    }

    /* Enable endpoint */
    ret = fi_enable(ep);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: fi_enable failed: %s", fi_strerror(-ret));
        return C_ERR;
    }

    if (rdmaSetupIoBuf(ctx, ep)) {
        return C_ERR;
    }

    return C_OK;
}

static void rdmaReleaseResource(RdmaContext *ctx) {
    rdmaDestroyIoBuf(ctx);

    if (ctx->cq) {
        fi_close(&ctx->cq->fid);
        ctx->cq = NULL;
    }

    if (ctx->domain) {
        fi_close(&ctx->domain->fid);
        ctx->domain = NULL;
    }

    if (ctx->fabric) {
        fi_close(&ctx->fabric->fid);
        ctx->fabric = NULL;
    }

    if (ctx->fi) {
        fi_freeinfo(ctx->fi);
        ctx->fi = NULL;
    }
}

static int rdmaAdjustSendbuf(RdmaContext *ctx, unsigned int length) {
    uint64_t access = FI_SEND | FI_RECV | FI_READ | FI_WRITE | FI_REMOTE_READ | FI_REMOTE_WRITE;
    int ret;

    if (length == ctx->tx_length) {
        return C_OK;
    }

    /* try to free old MR & buffer */
    if (ctx->tx_length) {
        fi_close(&ctx->tx.mr->fid);
        zlibc_free(ctx->tx.addr);
        ctx->tx_length = 0;
    }

    /* create a new buffer & MR */
    ctx->tx.addr = rdmaMemoryAlloc(length);
    ctx->tx_length = length;
    ret = fi_mr_reg(ctx->domain, ctx->tx.addr, length, access, 0, 0, 0, &ctx->tx.mr, NULL);
    if (ret) {
        serverRdmaError(server.neterr, "RDMA: reg send mr failed");
        serverLog(LL_WARNING, "RDMA: FATAL error, recv corrupted cmd");
        zlibc_free(ctx->tx.addr);
        ctx->tx.addr = NULL;
        ctx->tx_length = 0;
        return C_ERR;
    }
    ctx->tx.mr_desc = fi_mr_desc(ctx->tx.mr);

    return C_OK;
}

static int rdmaSendCommand(RdmaContext *ctx, struct fid_ep *ep, ValkeyRdmaCmd *cmd) {
    ValkeyRdmaCmd *_cmd;
    int i, ret;

    /* find an unused cmd buffer */
    for (i = VALKEY_RDMA_MAX_WQE; i < 2 * VALKEY_RDMA_MAX_WQE; i++) {
        _cmd = ctx->cmd_buf + i;
        if (_cmd->keepalive.opcode == VALKEY_RDMA_INVALID_OPCODE) {
            break;
        }
    }

    assert(i < 2 * VALKEY_RDMA_MAX_WQE);

    memcpy(_cmd, cmd, sizeof(ValkeyRdmaCmd));

    struct iovec iov = {
        .iov_base = _cmd,
        .iov_len = sizeof(ValkeyRdmaCmd),
    };
    struct fi_msg msg = {
        .msg_iov = &iov,
        .desc = &ctx->cmd_mr_desc,
        .iov_count = 1,
        .addr = FI_ADDR_UNSPEC,
        .context = _cmd,
    };

    ret = fi_sendmsg(ep, &msg, FI_COMPLETION);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: post send failed: %d", ret);
        return C_ERR;
    }

    return C_OK;
}

static int connRdmaRegisterRx(RdmaContext *ctx, struct fid_ep *ep) {
    ValkeyRdmaCmd cmd = {0};

    cmd.memory.opcode = htons(RegisterXferMemory);
    cmd.memory.addr = htonu64((uint64_t)(uintptr_t)ctx->rx.addr);
    cmd.memory.length = htonl(ctx->rx.length);
    cmd.memory.key = htonl((uint32_t)fi_mr_key(ctx->rx.mr));

    ctx->rx.offset = 0;
    ctx->rx.pos = 0;

    return rdmaSendCommand(ctx, ep, &cmd);
}

static int connRdmaGetFeature(RdmaContext *ctx, struct fid_ep *ep, ValkeyRdmaCmd *cmd) {
    ValkeyRdmaCmd _cmd = {0};

    _cmd.feature.opcode = htons(GetServerFeature);
    _cmd.feature.select = cmd->feature.select;
    _cmd.feature.features = htonu64(0); /* currently no feature support */

    return rdmaSendCommand(ctx, ep, &_cmd);
}

static int connRdmaSetFeature(RdmaContext *ctx, struct fid_ep *ep, ValkeyRdmaCmd *cmd) {
    UNUSED(ctx);
    UNUSED(ep);

    /* currently no feature support */
    if (ntohu64(cmd->feature.features)) return C_ERR;

    return C_OK;
}

static int rdmaHandleEstablished(struct fid_ep *ep, RdmaContext *ctx) {
    connRdmaRegisterRx(ctx, ep);

    return C_OK;
}

static inline void rdmaDelKeepalive(aeEventLoop *el, RdmaContext *ctx) {
    if (ctx->keepalive_te == AE_ERR) {
        return;
    }

    aeDeleteTimeEvent(el, ctx->keepalive_te);
    ctx->keepalive_te = AE_ERR;
}

static int rdmaHandleDisconnect(aeEventLoop *el, RdmaContext *ctx) {
    connection *conn = ctx->conn;
    rdma_connection *rdma_conn = (rdma_connection *)conn;

    rdmaDelKeepalive(el, ctx);
    conn->state = CONN_STATE_CLOSED;

    /* we can't close connection now, let's mark this connection as closed state */
    listAddNodeTail(pending_list, conn);
    rdma_conn->pending_list_node = listLast(pending_list);

    return C_OK;
}

static int connRdmaHandleRecv(RdmaContext *ctx, struct fid_ep *ep, ValkeyRdmaCmd *cmd, uint32_t byte_len) {
    if (unlikely(byte_len != sizeof(ValkeyRdmaCmd))) {
        serverLog(LL_WARNING, "RDMA: FATAL error, recv corrupted cmd");
        return C_ERR;
    }

    switch (ntohs(cmd->keepalive.opcode)) {
    case GetServerFeature: connRdmaGetFeature(ctx, ep, cmd); break;

    case SetClientFeature: connRdmaSetFeature(ctx, ep, cmd); break;

    case Keepalive: break;

    case RegisterXferMemory:
        ctx->tx_addr = (char *)(uintptr_t)ntohu64(cmd->memory.addr);
        ctx->tx.length = ntohl(cmd->memory.length);
        ctx->tx_key = ntohl(cmd->memory.key);
        ctx->tx.offset = 0;
        rdmaAdjustSendbuf(ctx, ctx->tx.length);
        break;

    default: serverLog(LL_WARNING, "RDMA: FATAL error, unknown cmd"); return C_ERR;
    }

    return rdmaPostRecv(ctx, ep, cmd);
}

static int connRdmaHandleSend(ValkeyRdmaCmd *cmd) {
    /* clear cmd and mark this cmd has already sent */
    memset(cmd, 0x00, sizeof(*cmd));
    cmd->keepalive.opcode = VALKEY_RDMA_INVALID_OPCODE;

    return C_OK;
}

static int connRdmaHandleRecvImm(RdmaContext *ctx, struct fid_ep *ep, ValkeyRdmaCmd *cmd, uint32_t byte_len) {
    assert(byte_len + ctx->rx.offset <= ctx->rx.length);

    ctx->rx.offset += byte_len;

    return rdmaPostRecv(ctx, ep, cmd);
}

static int connRdmaHandleWrite(RdmaContext *ctx, uint32_t byte_len) {
    UNUSED(ctx);
    UNUSED(byte_len);

    return C_OK;
}


static int connRdmaHandleCq(rdma_connection *rdma_conn) {
    struct fid_ep *ep = rdma_conn->ep;
    RdmaContext *ctx = ep->fid.context;
    struct fi_cq_data_entry cq_entry;
    struct fi_cq_err_entry cq_err;
    ValkeyRdmaCmd *cmd;
    ssize_t ret;

pollcq:
    ret = fi_cq_read(ctx->cq, &cq_entry, 1);
    if (ret == -FI_EAGAIN) {
        /* Re-arm CQ for next event notification */
        fi_cq_signal(ctx->cq);
        return C_OK;
    } else if (ret == -FI_EAVAIL) {
        /* Error available */
        fi_cq_readerr(ctx->cq, &cq_err, 0);
        if (rdma_conn->c.state == CONN_STATE_CONNECTED) {
            serverLog(LL_WARNING, "RDMA: CQ error: %s", fi_cq_strerror(ctx->cq, cq_err.prov_errno, cq_err.err_data, NULL, 0));
        }
        return C_ERR;
    } else if (ret < 0) {
        serverLog(LL_WARNING, "RDMA: fi_cq_read error: %s", fi_strerror(-ret));
        return C_ERR;
    }

    if (cq_entry.flags & FI_RECV) {
        cmd = (ValkeyRdmaCmd *)cq_entry.op_context;
        if (cq_entry.flags & FI_REMOTE_WRITE) {
            /* RDMA write with immediate data (remote write completed on our recv buffer) */
            if (connRdmaHandleRecvImm(ctx, ep, cmd, ntohl((uint32_t)cq_entry.data)) == C_ERR) {
                rdma_conn->c.state = CONN_STATE_ERROR;
                return C_ERR;
            }
        } else {
            /* Regular receive (command message) */
            if (connRdmaHandleRecv(ctx, ep, cmd, cq_entry.len) == C_ERR) {
                return C_ERR;
            }
        }
    } else if (cq_entry.flags & FI_WRITE) {
        /* RDMA write completion */
        if (connRdmaHandleWrite(ctx, cq_entry.len) == C_ERR) {
            return C_ERR;
        }
    } else if (cq_entry.flags & FI_SEND) {
        /* Send completion */
        cmd = (ValkeyRdmaCmd *)cq_entry.op_context;
        if (connRdmaHandleSend(cmd) == C_ERR) {
            return C_ERR;
        }
    } else {
        serverLog(LL_WARNING, "RDMA: unexpected CQ flags 0x[%lx]", (unsigned long)cq_entry.flags);
        return C_ERR;
    }

    goto pollcq;
}

static int connRdmaAccept(connection *conn, ConnectionCallbackFunc accept_handler) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    struct fid_ep *ep = rdma_conn->ep;
    RdmaContext *ctx = ep->fid.context;
    int ret = C_OK;

    if (conn->state != CONN_STATE_ACCEPTING) return C_ERR;

    conn->state = CONN_STATE_CONNECTED;

    connIncrRefs(conn);
    if (!callHandler(conn, accept_handler)) ret = C_ERR;
    connDecrRefs(conn);

    /* libfabric: use tx_attr.inject_size or a reasonable default for iovcnt */
    if (ctx->fi && ctx->fi->tx_attr) {
        conn->iovcnt = min((int)ctx->fi->tx_attr->iov_limit, IOV_MAX);
    } else {
        conn->iovcnt = 1;
    }
    ctx->conn = conn; /* save conn into RdmaContext */

    return ret;
}

static connection *connCreateRdma(void) {
    rdma_connection *rdma_conn = zcalloc(sizeof(rdma_connection));
    rdma_conn->c.type = &CT_RDMA;
    rdma_conn->c.fd = -1;
    rdma_conn->c.iovcnt = 1; /* at least 1, overwrite this on connect */

    return (connection *)rdma_conn;
}

static connection *connCreateAcceptedRdma(int fd, void *priv) {
    rdma_connection *rdma_conn = (rdma_connection *)connCreateRdma();
    rdma_conn->c.fd = fd;
    rdma_conn->c.state = CONN_STATE_ACCEPTING;
    rdma_conn->ep = priv;
    /* The CQ fd should be always non block */
    connNonBlock(&rdma_conn->c);

    return (connection *)rdma_conn;
}

static void connRdmaEventHandler(struct aeEventLoop *el, int fd, void *clientData, int mask) {
    rdma_connection *rdma_conn = (rdma_connection *)clientData;
    connection *conn = &rdma_conn->c;
    struct fid_ep *ep = rdma_conn->ep;
    RdmaContext *ctx = ep->fid.context;
    int ret = 0;

    UNUSED(el);
    UNUSED(fd);
    UNUSED(mask);

    ret = connRdmaHandleCq(rdma_conn);
    if (ret == C_ERR) {
        conn->state = CONN_STATE_ERROR;
        return;
    }

    /* uplayer should read all */
    while (!(rdma_conn->flags & RDMA_CONN_FLAG_POSTPONE_UPDATE_STATE) && ctx->rx.pos < ctx->rx.offset) {
        if (conn->read_handler && (callHandler(conn, conn->read_handler) == C_ERR)) {
            return;
        }
    }

    /* recv buf is full, register a new RX buffer */
    if (ctx->rx.pos == ctx->rx.length) {
        connRdmaRegisterRx(ctx, ep);
    }

    /* RDMA CQ has no POLLOUT event, try to send remaining buffer */
    if (!(rdma_conn->flags & RDMA_CONN_FLAG_POSTPONE_UPDATE_STATE) && ctx->tx.offset < ctx->tx.length && conn->write_handler) {
        callHandler(conn, conn->write_handler);
    }
}

static long long rdmaKeepaliveTimeProc(struct aeEventLoop *el, long long id, void *clientData) {
    rdma_connection *rdma_conn = clientData;
    struct fid_ep *ep = rdma_conn->ep;
    RdmaContext *ctx = ep->fid.context;
    connection *conn = ctx->conn;
    ValkeyRdmaCmd cmd = {0};

    UNUSED(el);
    UNUSED(id);
    if (conn->state != CONN_STATE_CONNECTED) {
        return AE_NOMORE;
    }

    cmd.keepalive.opcode = htons(Keepalive);
    if (rdmaSendCommand(ctx, ep, &cmd) != C_OK) {
        return AE_NOMORE;
    }

    return VALKEY_RDMA_KEEPALIVE_MS;
}

static int rdmaHandleConnect(aeEventLoop *el, char *err, struct fi_info *conn_info,
                             rdma_listener *listener, char *ip, size_t ip_len, int *port,
                             struct fid_ep **out_ep, rdma_connection **out_rdma_conn) {
    int ret = C_OK;
    struct fid_ep *ep = NULL;
    RdmaContext *ctx = NULL;
    struct sockaddr_storage *caddr;

    /* Extract client address from the connection info */
    caddr = (struct sockaddr_storage *)conn_info->dest_addr;
    if (caddr && caddr->ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)caddr;
        if (ip) inet_ntop(AF_INET, (void *)&(s->sin_addr), ip, ip_len);
        if (port) *port = ntohs(s->sin_port);
    } else if (caddr && caddr->ss_family == AF_INET6) {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)caddr;
        if (ip) inet_ntop(AF_INET6, (void *)&(s->sin6_addr), ip, ip_len);
        if (port) *port = ntohs(s->sin6_port);
    }

    ctx = zcalloc(sizeof(RdmaContext));
    ctx->ip = zstrdup(ip);
    ctx->port = *port;

    /* Create endpoint from connection info */
    ctx->fi = conn_info;
    ctx->fabric = listener->fabric;
    ret = fi_domain(ctx->fabric, conn_info, &ctx->domain, NULL);
    if (ret) {
        serverRdmaError(err, "RDMA: fi_domain failed: %s", fi_strerror(-ret));
        goto reject;
    }

    /* Create EQ for this connection */
    struct fi_eq_attr eq_attr = {
        .size = 32,
        .wait_obj = FI_WAIT_FD,
    };
    ret = fi_eq_open(ctx->fabric, &eq_attr, &ctx->eq, NULL);
    if (ret) {
        serverRdmaError(err, "RDMA: fi_eq_open failed: %s", fi_strerror(-ret));
        goto reject;
    }

    ret = fi_endpoint(ctx->domain, conn_info, &ep, ctx);
    if (ret) {
        serverRdmaError(err, "RDMA: fi_endpoint failed: %s", fi_strerror(-ret));
        goto reject;
    }
    ep->fid.context = ctx;

    /* Create a temporary rdma_connection to pass to keepalive timer */
    rdma_connection *rdma_conn = (rdma_connection *)connCreateRdma();
    rdma_conn->ep = ep;
    *out_rdma_conn = rdma_conn;

    ctx->keepalive_te = aeCreateTimeEvent(el, VALKEY_RDMA_KEEPALIVE_MS, rdmaKeepaliveTimeProc, rdma_conn, NULL);
    if (ctx->keepalive_te == AE_ERR) {
        goto reject;
    }

    if (rdmaCreateResource(ctx, ep) == C_ERR) {
        goto reject;
    }

    ret = fi_accept(ep, NULL, 0);
    if (ret) {
        serverRdmaError(err, "RDMA: fi_accept failed: %s", fi_strerror(-ret));
        goto free_rdma;
    }

    *out_ep = ep;
    return C_OK;

free_rdma:
    rdmaReleaseResource(ctx);
reject:
    if (ep) fi_reject(listener->pep, conn_info->handle, NULL, 0);

    return C_ERR;
}

static rdma_listener *rdmaFdToListener(connListener *listener, int fd) {
    for (int i = 0; i < listener->count; i++) {
        if (listener->fd[i] != fd) continue;

        return &rdma_listeners[i];
    }

    return NULL;
}

/*
 * rdmaAccept, actually it works as EQ event handler for passive endpoint.
 * accept a connection logic works in two steps:
 * 1, handle FI_CONNREQ and return CQ fd on success
 * 2, handle FI_CONNECTED and return C_OK on success
 */
static int
rdmaAccept(aeEventLoop *el, connListener *listener, char *err, int fd, char *ip, size_t ip_len, int *port, void **priv) {
    struct fi_eq_cm_entry eq_entry;
    struct fi_eq_err_entry eq_err;
    uint32_t event;
    ssize_t ret;
    rdma_listener *rdma_listener;

    rdma_listener = rdmaFdToListener(listener, fd);
    if (!rdma_listener) {
        serverPanic("RDMA: unexpected listen file descriptor");
    }

    ret = fi_eq_read(rdma_listener->eq, &event, &eq_entry, sizeof(eq_entry), 0);
    if (ret == -FI_EAGAIN) {
        return ANET_OK;
    } else if (ret == -FI_EAVAIL) {
        fi_eq_readerr(rdma_listener->eq, &eq_err, 0);
        serverLog(LL_WARNING, "RDMA: EQ error: %s", fi_eq_strerror(rdma_listener->eq, eq_err.prov_errno, eq_err.err_data, NULL, 0));
        return ANET_ERR;
    } else if (ret < 0) {
        serverLog(LL_WARNING, "RDMA: fi_eq_read failed: %s", fi_strerror(-ret));
        return ANET_ERR;
    }

    switch (event) {
    case FI_CONNREQ: {
        struct fid_ep *ep = NULL;
        rdma_connection *rdma_conn = NULL;
        int rc = rdmaHandleConnect(el, err, eq_entry.info, rdma_listener, ip, ip_len, port, &ep, &rdma_conn);
        if (rc == C_OK) {
            RdmaContext *ctx = ep->fid.context;
            *priv = ep;
            return ctx->cq_fd;
        }
        return rc;
    }

    case FI_CONNECTED: {
        struct fid_ep *ep = eq_entry.fid ? container_of(eq_entry.fid, struct fid_ep, fid) : NULL;
        if (ep) {
            RdmaContext *ctx = ep->fid.context;
            rdmaHandleEstablished(ep, ctx);
        }
        return C_OK;
    }

    case FI_SHUTDOWN: {
        struct fid_ep *ep = eq_entry.fid ? container_of(eq_entry.fid, struct fid_ep, fid) : NULL;
        if (ep) {
            RdmaContext *ctx = ep->fid.context;
            rdmaHandleDisconnect(el, ctx);
        }
        return C_OK;
    }

    default:
        serverLog(LL_NOTICE, "RDMA: listen EQ ignore event: %u", event);
        break;
    }

    return C_OK;
}

static void connRdmaAcceptHandler(aeEventLoop *el, int fd, void *privdata, int mask) {
    int cport = 0, cfd, max = server.max_new_conns_per_cycle;
    struct ClientFlags flags = {0};
    char cip[NET_IP_STR_LEN];
    void *connpriv = NULL;
    connListener *listener = (connListener *)privdata;
    UNUSED(el);
    UNUSED(mask);

    while (max--) {
        cfd = rdmaAccept(el, listener, server.neterr, fd, cip, sizeof(cip), &cport, &connpriv);
        if (cfd == ANET_ERR) {
            if (errno != EWOULDBLOCK) serverLog(LL_WARNING, "RDMA Accepting client connection: %s", server.neterr);
            return;
        } else if (cfd == ANET_OK)
            continue;

        serverLog(LL_VERBOSE, "RDMA Accepted %s:%d", cip, cport);
        acceptCommonHandler(connCreateAcceptedRdma(cfd, connpriv), flags, cip);
    }
}

static int connRdmaSetRwHandler(connection *conn) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    if (rdma_conn->flags & RDMA_CONN_FLAG_POSTPONE_UPDATE_STATE) return C_OK;

    /* IB channel only has POLLIN event */
    if (conn->read_handler || conn->write_handler) {
        if (aeCreateFileEvent(server.el, conn->fd, AE_READABLE, conn->type->ae_handler, conn) == AE_ERR) {
            return C_ERR;
        }
    } else {
        aeDeleteFileEvent(server.el, conn->fd, AE_READABLE);
    }

    return C_OK;
}

static int connRdmaSetWriteHandler(connection *conn, ConnectionCallbackFunc func, int barrier) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;

    if (conn->state != CONN_STATE_CONNECTED) {
        return C_OK;
    }

    conn->write_handler = func;
    if (barrier) {
        conn->flags |= CONN_FLAG_WRITE_BARRIER;
    } else {
        conn->flags &= ~CONN_FLAG_WRITE_BARRIER;
    }

    /* does this connection has pending write data? */
    if (func) {
        listAddNodeTail(pending_list, conn);
        rdma_conn->pending_list_node = listLast(pending_list);
    } else if (rdma_conn->pending_list_node) {
        listDelNode(pending_list, rdma_conn->pending_list_node);
        rdma_conn->pending_list_node = NULL;
    }

    return connRdmaSetRwHandler(conn);
}

static int connRdmaSetReadHandler(connection *conn, ConnectionCallbackFunc func) {
    conn->read_handler = func;

    return connRdmaSetRwHandler(conn);
}

static const char *connRdmaGetLastError(connection *conn) {
    return strerror(conn->last_errno);
}

static inline void rdmaConnectFailed(rdma_connection *rdma_conn) {
    connection *conn = &rdma_conn->c;

    conn->state = CONN_STATE_ERROR;
    conn->last_errno = ENETUNREACH;
}

static int rdmaConnect(RdmaContext *ctx, struct fid_ep *ep) {
    int ret;

    if (rdmaCreateResource(ctx, ep) == C_ERR) {
        return C_ERR;
    }

    ret = fi_connect(ep, ctx->fi->dest_addr, NULL, 0);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: fi_connect failed: %s", fi_strerror(-ret));
        return C_ERR;
    }

    anetNonBlock(NULL, ctx->cq_fd);
    anetCloexec(ctx->cq_fd);

    return C_OK;
}

/* Client-side EQ event handler for libfabric */
static void rdmaEQeventHandler(struct aeEventLoop *el, int fd, void *clientData, int mask) {
    rdma_connection *rdma_conn = (rdma_connection *)clientData;
    connection *conn = &rdma_conn->c;
    struct fid_ep *ep = rdma_conn->ep;
    RdmaContext *ctx = ep->fid.context;
    struct fi_eq_cm_entry eq_entry;
    struct fi_eq_err_entry eq_err;
    uint32_t event;
    ssize_t ret;

    UNUSED(el);
    UNUSED(fd);
    UNUSED(mask);

    ret = fi_eq_read(ctx->eq, &event, &eq_entry, sizeof(eq_entry), 0);
    if (ret == -FI_EAGAIN) {
        return;
    } else if (ret == -FI_EAVAIL) {
        fi_eq_readerr(ctx->eq, &eq_err, 0);
        serverLog(LL_WARNING, "RDMA: client EQ error: %s",
                  fi_eq_strerror(ctx->eq, eq_err.prov_errno, eq_err.err_data, NULL, 0));
        rdmaConnectFailed(rdma_conn);
        goto check_error;
    } else if (ret < 0) {
        serverLog(LL_WARNING, "RDMA: fi_eq_read failed: %s", fi_strerror(-ret));
        return;
    }

    switch (event) {
    case FI_CONNECTED:
        rdmaHandleEstablished(ep, ctx);
        conn->state = CONN_STATE_CONNECTED;
        conn->fd = ctx->cq_fd;
        if (conn->conn_handler) {
            callHandler(conn, conn->conn_handler);
        }
        break;

    case FI_SHUTDOWN:
        rdmaHandleDisconnect(el, ctx);
        break;

    default:
        serverLog(LL_NOTICE, "RDMA: client EQ ignore event: %u", event);
        break;
    }

check_error:
    /* connection error or closed by remote peer */
    if (conn->state == CONN_STATE_ERROR) {
        callHandler(conn, conn->conn_handler);
    }
}

/* Setup client-side connection resources using libfabric */
static int rdmaResolveAddr(rdma_connection *rdma_conn, const char *addr, int port, const char *src_addr) {
    struct fi_info *hints = NULL, *fi = NULL;
    RdmaContext *ctx = NULL;
    struct fid_ep *ep = NULL;
    char _port[6]; /* strlen("65535") */
    int ret = C_ERR;

    UNUSED(src_addr);
    ctx = zcalloc(sizeof(RdmaContext));
    if (!ctx) {
        serverLog(LL_WARNING, "RDMA: Out of memory");
        goto out;
    }

    snprintf(_port, 6, "%d", port);

    /* Setup hints for fi_getinfo */
    hints = fi_allocinfo();
    if (!hints) {
        serverLog(LL_WARNING, "RDMA: fi_allocinfo failed");
        goto out;
    }
    hints->caps = FI_MSG | FI_RMA | FI_RMA_EVENT;
    hints->ep_attr->type = FI_EP_MSG;
    hints->domain_attr->mr_mode = FI_MR_LOCAL | FI_MR_VIRT_ADDR | FI_MR_ALLOCATED | FI_MR_PROV_KEY;

    ret = fi_getinfo(FI_VERSION(1, 6), addr, _port, 0, hints, &fi);
    fi_freeinfo(hints);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: fi_getinfo failed: %s", fi_strerror(-ret));
        ret = C_ERR;
        goto out;
    }

    ctx->fi = fi;

    ret = fi_fabric(fi->fabric_attr, &ctx->fabric, NULL);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: fi_fabric failed: %s", fi_strerror(-ret));
        ret = C_ERR;
        goto out;
    }

    ret = fi_domain(ctx->fabric, fi, &ctx->domain, NULL);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: fi_domain failed: %s", fi_strerror(-ret));
        ret = C_ERR;
        goto out;
    }

    /* Create EQ for CM events */
    struct fi_eq_attr eq_attr = {
        .size = 32,
        .wait_obj = FI_WAIT_FD,
    };
    ret = fi_eq_open(ctx->fabric, &eq_attr, &ctx->eq, NULL);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: fi_eq_open failed: %s", fi_strerror(-ret));
        ret = C_ERR;
        goto out;
    }

    ret = fi_endpoint(ctx->domain, fi, &ep, ctx);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: fi_endpoint failed: %s", fi_strerror(-ret));
        ret = C_ERR;
        goto out;
    }
    ep->fid.context = ctx;
    rdma_conn->ep = ep;

    /* Get EQ fd for event loop */
    int eq_fd;
    ret = fi_control(&ctx->eq->fid, FI_GETWAIT, &eq_fd);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: fi_control FI_GETWAIT on EQ failed: %s", fi_strerror(-ret));
        ret = C_ERR;
        goto out;
    }

    if (anetNonBlock(NULL, eq_fd) != C_OK) {
        serverLog(LL_WARNING, "RDMA: set EQ fd non-block failed");
        ret = C_ERR;
        goto out;
    }

    ret = C_OK;

out:
    return ret;
}

static int connRdmaWait(connection *conn, long long start, long long timeout) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    long long remaining = timeout, wait, elapsed = 0;

    remaining = timeout - elapsed;
    wait = (remaining < VALKEY_RDMA_SYNCIO_RES) ? remaining : VALKEY_RDMA_SYNCIO_RES;
    aeWait(conn->fd, AE_READABLE, wait);
    elapsed = mstime() - start;
    if (elapsed >= timeout) {
        errno = ETIMEDOUT;
        return C_ERR;
    }

    if (connRdmaHandleCq(rdma_conn) == C_ERR) {
        conn->state = CONN_STATE_ERROR;
        return C_ERR;
    }

    return C_OK;
}

static int connRdmaConnect(connection *conn,
                           const char *addr,
                           int port,
                           const char *src_addr,
                           int multipath,
                           ConnectionCallbackFunc connect_handler) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    struct fid_ep *ep;
    RdmaContext *ctx;
    int eq_fd;

    /* RDMA does not support multipath, and there is no outgoing RDMA connection at the current stage */
    assert(!multipath);

    if (rdmaResolveAddr(rdma_conn, addr, port, src_addr) == C_ERR) {
        return C_ERR;
    }

    ep = rdma_conn->ep;
    ctx = ep->fid.context;

    /* Get EQ fd for event loop */
    if (fi_control(&ctx->eq->fid, FI_GETWAIT, &eq_fd)) {
        return C_ERR;
    }

    if (aeCreateFileEvent(server.el, eq_fd, AE_READABLE, rdmaEQeventHandler, conn) == AE_ERR) {
        return C_ERR;
    }

    /* Initiate the connect */
    if (rdmaConnect(ctx, ep) == C_ERR) {
        return C_ERR;
    }

    conn->conn_handler = connect_handler;

    return C_OK;
}

static int connRdmaBlockingConnect(connection *conn, const char *addr, int port, long long timeout) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    struct fid_ep *ep;
    RdmaContext *ctx;
    int eq_fd;
    long long start = mstime();

    if (rdmaResolveAddr(rdma_conn, addr, port, NULL) == C_ERR) {
        return C_ERR;
    }

    ep = rdma_conn->ep;
    ctx = ep->fid.context;

    if (fi_control(&ctx->eq->fid, FI_GETWAIT, &eq_fd)) {
        return C_ERR;
    }

    if (aeCreateFileEvent(server.el, eq_fd, AE_READABLE, rdmaEQeventHandler, conn) == AE_ERR) {
        return C_ERR;
    }

    /* Initiate the connect */
    if (rdmaConnect(ctx, ep) == C_ERR) {
        return C_ERR;
    }

    do {
        if (connRdmaWait(conn, start, timeout) == C_ERR) {
            return C_ERR;
        }
    } while (conn->state != CONN_STATE_CONNECTED);

    return C_OK;
}

static void connRdmaShutdown(connection *conn) {
    UNUSED(conn);
}

static void connRdmaClose(connection *conn) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    struct fid_ep *ep = rdma_conn->ep;
    RdmaContext *ctx;

    if (conn->fd != -1) {
        aeDeleteFileEvent(server.el, conn->fd, AE_READABLE);
        conn->fd = -1;
    }

    /* If called from within a handler, schedule the close but
     * keep the connection until the handler returns.
     */
    if (connHasRefs(conn)) {
        conn->flags |= CONN_FLAG_CLOSE_SCHEDULED;
        return;
    }

    if (!ep) {
        return;
    }

    ctx = ep->fid.context;
    rdmaDelKeepalive(server.el, ctx);
    fi_shutdown(ep, 0);

    /* poll all CQ before close */
    connRdmaHandleCq(rdma_conn);
    rdmaReleaseResource(ctx);

    fi_close(&ep->fid);

    if (ctx->eq) {
        int eq_fd;
        if (fi_control(&ctx->eq->fid, FI_GETWAIT, &eq_fd) == 0) {
            aeDeleteFileEvent(server.el, eq_fd, AE_READABLE);
        }
        fi_close(&ctx->eq->fid);
    }

    rdma_conn->ep = NULL;
    zfree(ctx);
    zfree(conn);
}

static size_t connRdmaSend(connection *conn, const void *data, size_t data_len) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    struct fid_ep *ep = rdma_conn->ep;
    RdmaContext *ctx = ep->fid.context;
    uint32_t off = ctx->tx.offset;
    char *addr = ctx->tx.addr + off;
    uint64_t remote_addr = (uint64_t)(uintptr_t)(ctx->tx_addr + ctx->tx.offset);
    ssize_t ret;
    uint64_t flags;

    if (connRdmaAllowCommand()) {
        return C_ERR;
    }

    memcpy(addr, data, data_len);

    struct iovec iov = {
        .iov_base = addr,
        .iov_len = data_len,
    };
    struct fi_rma_iov rma_iov = {
        .addr = remote_addr,
        .len = data_len,
        .key = ctx->tx_key,
    };
    struct fi_msg_rma msg = {
        .msg_iov = &iov,
        .desc = &ctx->tx.mr_desc,
        .iov_count = 1,
        .addr = FI_ADDR_UNSPEC,
        .rma_iov = &rma_iov,
        .rma_iov_count = 1,
        .context = NULL,
        .data = htonl((uint32_t)data_len),
    };

    /* Use FI_COMPLETION selectively like IBV_SEND_SIGNALED */
    flags = FI_REMOTE_CQ_DATA;
    if ((++ctx->tx_ops % (VALKEY_RDMA_MAX_WQE / 2)) == 0) {
        flags |= FI_COMPLETION;
    }

    ret = fi_writemsg(ep, &msg, flags);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: fi_writemsg failed: %s", fi_strerror(-ret));
        conn->state = CONN_STATE_ERROR;
        return C_ERR;
    }

    ctx->tx.offset += data_len;

    return data_len;
}

static int connRdmaWrite(connection *conn, const void *data, size_t data_len) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    struct fid_ep *ep = rdma_conn->ep;
    RdmaContext *ctx = ep->fid.context;
    uint32_t towrite;

    if (connRdmaAllowRW(conn)) {
        return C_ERR;
    }

    assert(ctx->tx.offset <= ctx->tx.length);
    towrite = MIN(ctx->tx.length - ctx->tx.offset, data_len);
    if (!towrite) {
        return 0;
    }

    return connRdmaSend(conn, data, towrite);
}

static int connRdmaWritev(connection *conn, const struct iovec *iov, int iovcnt) {
    int ret, nwritten = 0;

    for (int i = 0; i < iovcnt; i++) {
        ret = connRdmaWrite(conn, iov[i].iov_base, iov[i].iov_len);
        if (ret == C_ERR) return C_ERR;
        nwritten += ret;
    }

    return nwritten;
}

static inline uint32_t rdmaRead(RdmaContext *ctx, void *buf, size_t buf_len) {
    uint32_t toread;

    toread = MIN(ctx->rx.offset - ctx->rx.pos, buf_len);

    assert(ctx->rx.pos + toread <= ctx->rx.length);
    memcpy(buf, ctx->rx.addr + ctx->rx.pos, toread);

    ctx->rx.pos += toread;

    return toread;
}

static int connRdmaRead(connection *conn, void *buf, size_t buf_len) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    struct fid_ep *ep = rdma_conn->ep;
    RdmaContext *ctx = ep->fid.context;

    if (connRdmaAllowRW(conn)) {
        return C_ERR;
    }

    /* No more data to read */
    if (ctx->rx.pos == ctx->rx.offset) {
        return -1;
    }

    assert(ctx->rx.pos < ctx->rx.offset);

    return rdmaRead(ctx, buf, buf_len);
}

static ssize_t connRdmaSyncWrite(connection *conn, char *ptr, ssize_t size, long long timeout) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    struct fid_ep *ep = rdma_conn->ep;
    RdmaContext *ctx = ep->fid.context;
    ssize_t nwritten = 0;
    long long start = mstime();
    uint32_t towrite;

    if (connRdmaAllowRW(conn)) {
        return C_ERR;
    }

    assert(ctx->tx.offset <= ctx->tx.length);
    if (ctx->tx.offset < ctx->tx.length) {
        /* TX buffer is available */
        goto copy;
    }

wait:
    if (connRdmaWait(conn, start, timeout) == C_ERR) {
        return C_ERR;
    }

    if (unlikely(!ctx->tx.mr)) {
        goto wait;
    }

copy:
    towrite = MIN(ctx->tx.length - ctx->tx.offset, size - nwritten);
    if (connRdmaSend(conn, ptr, towrite) == (size_t)C_ERR) {
        return C_ERR;
    } else {
        ptr += towrite;
        nwritten += towrite;
    }

    if (nwritten < size) {
        goto wait;
    }

    return size;
}

static ssize_t connRdmaSyncRead(connection *conn, char *ptr, ssize_t size, long long timeout) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    struct fid_ep *ep = rdma_conn->ep;
    RdmaContext *ctx = ep->fid.context;
    ssize_t nread = 0;
    long long start = mstime();
    uint32_t toread;

    if (connRdmaAllowRW(conn)) {
        return C_ERR;
    }

    assert(ctx->rx.pos <= ctx->rx.offset);
    if (ctx->rx.pos < ctx->rx.offset) {
        goto copy;
    }

wait:
    if (connRdmaWait(conn, start, timeout) == C_ERR) {
        return C_ERR;
    }

copy:
    toread = rdmaRead(ctx, ptr, size - nread);
    ptr += toread;
    nread += toread;
    if (nread < size) {
        goto wait;
    }

    return size;
}

static ssize_t connRdmaSyncReadLine(connection *conn, char *ptr, ssize_t size, long long timeout) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    struct fid_ep *ep = rdma_conn->ep;
    RdmaContext *ctx = ep->fid.context;
    ssize_t nread = 0;
    long long start = mstime();
    uint32_t toread;
    char *c;
    char nl = 0;

    if (connRdmaAllowRW(conn)) {
        return C_ERR;
    }

    assert(ctx->rx.pos <= ctx->rx.offset);
    if (ctx->rx.pos < ctx->rx.offset) {
        goto copy;
    }

wait:
    if (connRdmaWait(conn, start, timeout) == C_ERR) {
        return C_ERR;
    }

copy:
    for (toread = 0; toread <= ctx->rx.offset - ctx->rx.pos; toread++) {
        c = ctx->rx.addr + ctx->rx.pos + toread;
        if (*c == '\n') {
            *c = '\0';
            if (toread && *(c - 1) == '\r') {
                *(c - 1) = '\0';
            }
            nl = 1;
            break;
        }
    }

    toread = rdmaRead(ctx, ptr, MIN(toread + nl, size - nread));
    ptr += toread;
    nread += toread;
    if (nl) {
        return nread;
    }

    if (nread < size) {
        goto wait;
    }

    return size;
}

static int connRdmaGetType(void) {
    return CONN_TYPE_RDMA;
}

static int rdmaServer(char *err, int port, char *bindaddr, int af, rdma_listener *rdma_listener) {
    int ret = ANET_OK;
    char _port[6]; /* strlen("65535") */
    struct fi_info *hints = NULL, *fi = NULL;
    struct fid_fabric *fabric = NULL;
    struct fid_pep *pep = NULL;
    struct fid_eq *eq = NULL;

    if (bindaddr && !strcmp("*", bindaddr)) bindaddr = NULL;
    if (af == AF_INET6 && bindaddr && !strcmp("::*", bindaddr)) bindaddr = NULL;

    snprintf(_port, 6, "%d", port);

    /* Setup hints for passive endpoint */
    hints = fi_allocinfo();
    if (!hints) {
        serverRdmaError(err, "RDMA: fi_allocinfo failed");
        return ANET_ERR;
    }
    hints->caps = FI_MSG | FI_RMA | FI_RMA_EVENT;
    hints->ep_attr->type = FI_EP_MSG;
    hints->domain_attr->mr_mode = FI_MR_LOCAL | FI_MR_VIRT_ADDR | FI_MR_ALLOCATED | FI_MR_PROV_KEY;
    if (af == AF_INET6) {
        hints->addr_format = FI_SOCKADDR_IN6;
    } else {
        hints->addr_format = FI_SOCKADDR_IN;
    }

    ret = fi_getinfo(FI_VERSION(1, 6), bindaddr, _port, FI_SOURCE, hints, &fi);
    fi_freeinfo(hints);
    if (ret) {
        serverRdmaError(err, "RDMA: fi_getinfo failed: %s", fi_strerror(-ret));
        return ANET_ERR;
    }

    ret = fi_fabric(fi->fabric_attr, &fabric, NULL);
    if (ret) {
        serverRdmaError(err, "RDMA: fi_fabric failed: %s", fi_strerror(-ret));
        goto error;
    }

    /* Create EQ for listening */
    struct fi_eq_attr eq_attr = {
        .size = 32,
        .wait_obj = FI_WAIT_FD,
    };
    ret = fi_eq_open(fabric, &eq_attr, &eq, NULL);
    if (ret) {
        serverRdmaError(err, "RDMA: fi_eq_open failed: %s", fi_strerror(-ret));
        goto error;
    }

    ret = fi_passive_ep(fabric, fi, &pep, NULL);
    if (ret) {
        serverRdmaError(err, "RDMA: fi_passive_ep failed: %s", fi_strerror(-ret));
        goto error;
    }

    ret = fi_pep_bind(pep, &eq->fid, 0);
    if (ret) {
        serverRdmaError(err, "RDMA: fi_pep_bind failed: %s", fi_strerror(-ret));
        goto error;
    }

    ret = fi_listen(pep);
    if (ret) {
        serverRdmaError(err, "RDMA: fi_listen failed: %s", fi_strerror(-ret));
        goto error;
    }

    rdma_listener->pep = pep;
    rdma_listener->eq = eq;
    rdma_listener->fabric = fabric;
    rdma_listener->fi = fi;
    return ANET_OK;

error:
    if (pep) fi_close(&pep->fid);
    if (eq) fi_close(&eq->fid);
    if (fabric) fi_close(&fabric->fid);
    if (fi) fi_freeinfo(fi);
    return ANET_ERR;
}

static int connRdmaIsLocal(connection *conn) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    struct fid_ep *ep = rdma_conn->ep;
    RdmaContext *ctx = ep->fid.context;
    size_t laddr_len = 0, raddr_len = 0;
    struct sockaddr_storage laddr_buf, raddr_buf;

    laddr_len = sizeof(laddr_buf);
    raddr_len = sizeof(raddr_buf);

    if (fi_getname(&ep->fid, &laddr_buf, &laddr_len)) return -1;
    if (fi_getpeer(ep, &raddr_buf, &raddr_len)) return -1;

    UNUSED(ctx);

    if (laddr_buf.ss_family == AF_INET) {
        struct sockaddr_in *lsa4 = (struct sockaddr_in *)&laddr_buf;
        struct sockaddr_in *rsa4 = (struct sockaddr_in *)&raddr_buf;
        return !memcmp(&lsa4->sin_addr, &rsa4->sin_addr, sizeof(lsa4->sin_addr));
    } else if (laddr_buf.ss_family == AF_INET6) {
        struct sockaddr_in6 *lsa6 = (struct sockaddr_in6 *)&laddr_buf;
        struct sockaddr_in6 *rsa6 = (struct sockaddr_in6 *)&raddr_buf;
        return !memcmp(&lsa6->sin6_addr, &rsa6->sin6_addr, sizeof(lsa6->sin6_addr));
    }

    return -1;
}

int connRdmaListen(connListener *listener) {
    int j, ret;
    char **bindaddr = listener->bindaddr;
    int bindaddr_count = listener->bindaddr_count;
    int port = listener->port;
    char *default_bindaddr[2] = {"*", "-::*"};
    rdma_listener *rdma_listener;

    assert(server.proto_max_bulk_len <= 512ll * 1024 * 1024);

    /* Force binding of 0.0.0.0 if no bind address is specified. */
    if (listener->bindaddr_count == 0) {
        bindaddr_count = 2;
        bindaddr = default_bindaddr;
    }

    rdma_listeners = rdma_listener = zcalloc_num(bindaddr_count, sizeof(*rdma_listener));
    for (j = 0; j < bindaddr_count; j++) {
        char *addr = bindaddr[j];
        int optional = *addr == '-';

        if (optional) addr++;
        if (strchr(addr, ':')) {
            /* Bind IPv6 address. */
            ret = rdmaServer(server.neterr, port, addr, AF_INET6, rdma_listener);
        } else {
            /* Bind IPv4 address. */
            ret = rdmaServer(server.neterr, port, addr, AF_INET, rdma_listener);
        }

        if (ret == ANET_ERR) {
            serverLog(LL_WARNING, "RDMA: Could not create server for %s:%d: %s", addr, port, server.neterr);

            return C_ERR;
        }

        int fd;
        if (fi_control(&rdma_listener->eq->fid, FI_GETWAIT, &fd)) {
            serverLog(LL_WARNING, "RDMA: fi_control FI_GETWAIT failed for listener EQ");
            return C_ERR;
        }
        anetNonBlock(NULL, fd);
        anetCloexec(fd);
        listener->fd[listener->count++] = fd;
        rdma_listener++;
    }

    rdma_config = listener->priv;
    return C_OK;
}

static void connRdmaCloseListener(connListener *listener) {
    /* Close old servers */
    for (int i = 0; i < listener->count; i++) {
        if (listener->fd[i] == -1) continue;

        aeDeleteFileEvent(server.el, listener->fd[i], AE_READABLE);
        listener->fd[i] = -1;
        struct rdma_listener *rdma_listener = &rdma_listeners[i];
        if (rdma_listener->pep) fi_close(&rdma_listener->pep->fid);
        if (rdma_listener->eq) fi_close(&rdma_listener->eq->fid);
        if (rdma_listener->fabric) fi_close(&rdma_listener->fabric->fid);
        if (rdma_listener->fi) fi_freeinfo(rdma_listener->fi);
    }

    listener->count = 0;
    zfree(rdma_listeners);
    rdma_listeners = NULL;
    rdma_config = NULL;
}

static int connRdmaAddr(connection *conn, char *ip, size_t ip_len, int *port, int remote) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    struct fid_ep *ep = rdma_conn->ep;
    struct sockaddr_storage ss_buf;
    size_t ss_len = sizeof(ss_buf);
    struct sockaddr_in *sa4;
    struct sockaddr_in6 *sa6;
    int ret;

    if (remote) {
        ret = fi_getpeer(ep, &ss_buf, &ss_len);
    } else {
        ret = fi_getname(&ep->fid, &ss_buf, &ss_len);
    }

    if (ret) {
        goto error;
    }

    if (ss_buf.ss_family == AF_INET) {
        sa4 = (struct sockaddr_in *)&ss_buf;
        if (ip) {
            if (inet_ntop(AF_INET, (void *)&(sa4->sin_addr), ip, ip_len) == NULL) {
                goto error;
            }
        }

        if (port) {
            *port = ntohs(sa4->sin_port);
        }
    } else if (ss_buf.ss_family == AF_INET6) {
        sa6 = (struct sockaddr_in6 *)&ss_buf;
        if (ip) {
            if (inet_ntop(AF_INET6, (void *)&(sa6->sin6_addr), ip, ip_len) == NULL) {
                goto error;
            }
        }

        if (port) {
            *port = ntohs(sa6->sin6_port);
        }
    } else {
        /* TODO IB protocol */
        goto error;
    }

    return 0;

error:
    if (ip) {
        if (ip_len >= 2) {
            ip[0] = '?';
            ip[1] = '\0';
        } else if (ip_len == 1) {
            ip[0] = '\0';
        }
    }

    if (port) *port = 0;

    return -1;
}

static void rdmaInit(void) {
    pending_list = listCreate();
    page_size = sysconf(_SC_PAGESIZE);

    VALKEY_BUILD_BUG_ON(sizeof(ValkeyRdmaFeature) != 32);
    VALKEY_BUILD_BUG_ON(sizeof(ValkeyRdmaKeepalive) != 32);
    VALKEY_BUILD_BUG_ON(sizeof(ValkeyRdmaMemory) != 32);
    VALKEY_BUILD_BUG_ON(sizeof(ValkeyRdmaCmd) != 32);

    /* libfabric handles fork safety internally via the verbs provider */
}

static int rdmaHasPendingData(void) {
    if (!pending_list) return 0;

    return listLength(pending_list) > 0;
}

static int rdmaProcessPendingData(void) {
    listIter li;
    listNode *ln;
    rdma_connection *rdma_conn;
    connection *conn;
    int processed = 0;

    listRewind(pending_list, &li);
    while ((ln = listNext(&li))) {
        rdma_conn = listNodeValue(ln);
        if (rdma_conn->flags & RDMA_CONN_FLAG_POSTPONE_UPDATE_STATE) continue;
        conn = &rdma_conn->c;

        /* a connection can be disconnected by remote peer, CM event mark state as CONN_STATE_CLOSED, kick connection
         * read/write handler to close connection */
        if (conn->state == CONN_STATE_ERROR || conn->state == CONN_STATE_CLOSED) {
            listDelNode(pending_list, rdma_conn->pending_list_node);
            rdma_conn->pending_list_node = NULL;
            /* Invoke both read_handler and write_handler, unless read_handler
               returns 0, indicating the connection has closed, in which case
               write_handler will be skipped. */
            if (callHandler(conn, conn->read_handler)) {
                callHandler(conn, conn->write_handler);
            }

            ++processed;
            continue;
        }

        connRdmaEventHandler(NULL, -1, rdma_conn, 0);
        ++processed;
    }

    return processed;
}

static void postPoneUpdateRdmaState(struct connection *conn, int postpone) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    if (postpone) {
        rdma_conn->flags |= RDMA_CONN_FLAG_POSTPONE_UPDATE_STATE;
    } else {
        rdma_conn->flags &= ~RDMA_CONN_FLAG_POSTPONE_UPDATE_STATE;
    }
}

static void updateRdmaState(struct connection *conn) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    connRdmaSetRwHandler(conn);
    connRdmaEventHandler(NULL, -1, rdma_conn, 0);
}

static ConnectionType CT_RDMA = {
    /* connection type */
    .get_type = connRdmaGetType,

    /* connection type initialize & finalize & configure */
    .init = rdmaInit,
    .cleanup = NULL,

    /* ae & accept & listen & error & address handler */
    .ae_handler = connRdmaEventHandler,
    .accept_handler = connRdmaAcceptHandler,
    //.cluster_accept_handler = NULL,
    .is_local = connRdmaIsLocal,
    .listen = connRdmaListen,
    .closeListener = connRdmaCloseListener,
    .addr = connRdmaAddr,

    /* create/close connection */
    .conn_create = connCreateRdma,
    .conn_create_accepted = connCreateAcceptedRdma,
    .shutdown = connRdmaShutdown,
    .close = connRdmaClose,

    /* connect & accept */
    .connect = connRdmaConnect,
    .blocking_connect = connRdmaBlockingConnect,
    .accept = connRdmaAccept,

    /* IO */
    .write = connRdmaWrite,
    .writev = connRdmaWritev,
    .read = connRdmaRead,
    .set_write_handler = connRdmaSetWriteHandler,
    .set_read_handler = connRdmaSetReadHandler,
    .get_last_error = connRdmaGetLastError,
    .sync_write = connRdmaSyncWrite,
    .sync_read = connRdmaSyncRead,
    .sync_readline = connRdmaSyncReadLine,

    /* pending data */
    .has_pending_data = rdmaHasPendingData,
    .process_pending_data = rdmaProcessPendingData,
    .postpone_update_state = postPoneUpdateRdmaState,
    .update_state = updateRdmaState,

    /* Miscellaneous */
    .connIntegrityChecked = NULL,
};

ConnectionType *connectionTypeRdma(void) {
    static ConnectionType *ct_rdma = NULL;

    if (ct_rdma != NULL) return ct_rdma;

    ct_rdma = connectionByType(CONN_TYPE_RDMA);
    serverAssert(ct_rdma != NULL);

    return ct_rdma;
}

int RegisterConnectionTypeRdma(void) {
    return connTypeRegister(&CT_RDMA);
}

#else

int RegisterConnectionTypeRdma(void) {
    serverLog(LL_VERBOSE, "Connection type %s not builtin", getConnectionTypeName(CONN_TYPE_RDMA));
    return C_ERR;
}

#endif

#if defined(BUILD_RDMA_MODULE) && BUILD_RDMA_MODULE == 2 /* BUILD_MODULE */

#include "release.h"


int ValkeyModule_OnLoad(void *ctx, ValkeyModuleString **argv, int argc) {
    UNUSED(argv);
    UNUSED(argc);

    /* Connection modules MUST be part of the same build as valkey. */
    if (strcmp(REDIS_BUILD_ID_RAW, serverBuildIdRaw())) {
        serverLog(LL_NOTICE, "Connection type %s was not built together with the valkey-server used.", getConnectionTypeName(CONN_TYPE_RDMA));
        return VALKEYMODULE_ERR;
    }

    if (ValkeyModule_Init(ctx, getConnectionTypeName(CONN_TYPE_RDMA), 1, VALKEYMODULE_APIVER_1) == VALKEYMODULE_ERR) return VALKEYMODULE_ERR;

    /* Connection modules is available only bootup. */
    if ((ValkeyModule_GetContextFlags(ctx) & VALKEYMODULE_CTX_FLAGS_SERVER_STARTUP) == 0) {
        serverLog(LL_NOTICE, "Connection type %s can be loaded only during bootup", getConnectionTypeName(CONN_TYPE_RDMA));
        return VALKEYMODULE_ERR;
    }

    ValkeyModule_SetModuleOptions(ctx, VALKEYMODULE_OPTIONS_HANDLE_REPL_ASYNC_LOAD | VALKEYMODULE_OPTIONS_HANDLE_ATOMIC_SLOT_MIGRATION);

    if (connTypeRegister(&CT_RDMA) != C_OK) return VALKEYMODULE_ERR;

    return VALKEYMODULE_OK;
}

int ValkeyModule_OnUnload(void *arg) {
    UNUSED(arg);
    serverLog(LL_NOTICE, "Connection type %s can not be unloaded", getConnectionTypeName(CONN_TYPE_RDMA));
    return VALKEYMODULE_ERR;
}

#endif /* BUILD_RDMA_MODULE */

#else /* __linux__ */

int RegisterConnectionTypeRdma(void) {
    serverLog(LL_VERBOSE, "Connection type %s is supported on Linux only", getConnectionTypeName(CONN_TYPE_RDMA));
    return C_ERR;
}

#endif /* __linux__ */
