/* ==========================================================================
 * rdma.c - support RDMA protocol for transport layer.
 * --------------------------------------------------------------------------
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
#include "rdma_transport.h"

#include <arpa/inet.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/mman.h>

/* Include the selected transport backend */
#if defined(USE_RDMA_FABRIC)
#include "rdma_transport_fabric.h"
#elif defined(USE_RDMA_VERBS) || !defined(USE_RDMA_FABRIC)
/* Default to verbs for backward compatibility */
#include <rdma/rdma_cma.h>
#include "rdma_transport_verbs.h"
#endif

/* Select the active transport provider */
static const rdmaTransportOps *transport_ops =
#if defined(USE_RDMA_FABRIC)
    &rdmaTransportFabricOps;
#else
    &rdmaTransportVerbsOps;
#endif

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
    rdmaTransportEP *ep;
    int flags;
    int last_errno;
    listNode *pending_list_node;
} rdma_connection;

typedef struct RdmaXfer {
    rdmaTransportMR *mr; /* memory region of the transfer buffer */
    char *addr;          /* address of transfer buffer in local memory */
    uint32_t length;     /* bytes of transfer buffer */
    uint32_t offset;     /* the offset of consumed transfer buffer */
    uint32_t pos;        /* the position in use of the transfer buffer */
} RdmaXfer;

typedef struct RdmaContext {
    connection *conn;
    char *ip;
    int port;
    long long keepalive_te; /* RDMA has no transport layer keepalive */
    rdmaTransportDomain *domain;
    rdmaTransportEQ *cm_channel;
    rdmaTransportCQ *cq;

    /* TX */
    RdmaXfer tx;
    char *tx_addr;      /* remote transfer buffer address */
    uint32_t tx_key;    /* remote transfer buffer key */
    uint32_t tx_length; /* remote transfer buffer length */
    uint32_t tx_offset; /* remote transfer buffer offset */
    uint32_t tx_ops;    /* operations on remote transfer */

    /* RX */
    RdmaXfer rx;

    /* CMD 0 ~ VALKEY_RDMA_MAX_WQE for recv buffer
     * VALKEY_RDMA_MAX_WQE ~ 2 * VALKEY_RDMA_MAX_WQE -1 for send buffer */
    ValkeyRdmaCmd *cmd_buf;
    rdmaTransportMR *cmd_mr;
} RdmaContext;

typedef struct rdma_listener {
    rdmaTransportPEP *pep;
    rdmaTransportEQ *eq;
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

static int rdmaPostRecv(RdmaContext *ctx, rdmaTransportEP *ep, ValkeyRdmaCmd *cmd) {
    int ret;

    if (connRdmaAllowCommand()) {
        return C_ERR;
    }

    ret = transport_ops->post_recv(ep, cmd, sizeof(ValkeyRdmaCmd),
                                   ctx->cmd_mr, (uint64_t)(uintptr_t)cmd);
    if (ret && (ret != EAGAIN)) {
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
        transport_ops->dereg_mr(ctx->rx.mr);
        ctx->rx.mr = NULL;
    }

    rdmaMemoryFree(ctx->rx.addr, ctx->rx.length);
    ctx->rx.addr = NULL;

    if (ctx->tx.mr) {
        transport_ops->dereg_mr(ctx->tx.mr);
        ctx->tx.mr = NULL;
    }

    rdmaMemoryFree(ctx->tx.addr, ctx->tx.length);
    ctx->tx.addr = NULL;

    if (ctx->cmd_mr) {
        transport_ops->dereg_mr(ctx->cmd_mr);
        ctx->cmd_mr = NULL;
    }

    rdmaMemoryFree(ctx->cmd_buf, sizeof(ValkeyRdmaCmd) * VALKEY_RDMA_MAX_WQE * 2);
    ctx->cmd_buf = NULL;
}

static int rdmaSetupIoBuf(RdmaContext *ctx, rdmaTransportEP *ep) {
    int access = RDMA_TRANSPORT_ACCESS_LOCAL_WRITE;
    size_t length = sizeof(ValkeyRdmaCmd) * VALKEY_RDMA_MAX_WQE * 2;
    ValkeyRdmaCmd *cmd;
    int i;

    /* setup CMD buf & MR */
    ctx->cmd_buf = rdmaMemoryAlloc(length);
    ctx->cmd_mr = transport_ops->reg_mr(ctx->domain, ctx->cmd_buf, length, access);
    if (!ctx->cmd_mr) {
        serverLog(LL_WARNING, "RDMA: reg mr for CMD failed");
        goto destroy_iobuf;
    }

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
    access = RDMA_TRANSPORT_ACCESS_LOCAL_WRITE | RDMA_TRANSPORT_ACCESS_REMOTE_READ | RDMA_TRANSPORT_ACCESS_REMOTE_WRITE;
    length = rdma_config->rx_size;
    ctx->rx.addr = rdmaMemoryAlloc(length);
    ctx->rx.length = length;
    ctx->rx.mr = transport_ops->reg_mr(ctx->domain, ctx->rx.addr, length, access);
    if (!ctx->rx.mr) {
        serverLog(LL_WARNING, "RDMA: reg mr for recv buffer failed");
        goto destroy_iobuf;
    }

    return C_OK;

destroy_iobuf:
    rdmaDestroyIoBuf(ctx);
    return C_ERR;
}

static int rdmaCreateResource(RdmaContext *ctx, rdmaTransportEP *ep) {
    int ret = C_OK;
    int comp_vector = rdma_config->completion_vector;
    int max_sge;

    max_sge = transport_ops->query_device_max_sge(ep);
    if (max_sge < 0) {
        serverLog(LL_WARNING, "RDMA: query device failed");
        return C_ERR;
    }

    ctx->domain = transport_ops->alloc_domain(ep);
    if (!ctx->domain) {
        serverLog(LL_WARNING, "RDMA: alloc domain failed");
        return C_ERR;
    }

    ctx->cq = transport_ops->create_cq(ep, VALKEY_RDMA_MAX_WQE * 2, ctx->domain, comp_vector);
    if (!ctx->cq) {
        serverLog(LL_WARNING, "RDMA: create cq failed");
        return C_ERR;
    }

    rdmaTransportEPAttr ep_attr = {0};
    ep_attr.max_send_wr = VALKEY_RDMA_MAX_WQE;
    ep_attr.max_recv_wr = VALKEY_RDMA_MAX_WQE;
    ep_attr.max_send_sge = max_sge;
    ep_attr.max_recv_sge = 1;
    ep_attr.send_cq = ctx->cq;
    ep_attr.recv_cq = ctx->cq;
    ret = transport_ops->create_ep(ep, ctx->domain, &ep_attr);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: create endpoint failed");
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
        transport_ops->destroy_cq(ctx->cq);
    }

    if (ctx->domain) {
        transport_ops->free_domain(ctx->domain);
    }
}

static int rdmaAdjustSendbuf(RdmaContext *ctx, unsigned int length) {
    int access = RDMA_TRANSPORT_ACCESS_LOCAL_WRITE | RDMA_TRANSPORT_ACCESS_REMOTE_READ | RDMA_TRANSPORT_ACCESS_REMOTE_WRITE;

    if (length == ctx->tx_length) {
        return C_OK;
    }

    /* try to free old MR & buffer */
    if (ctx->tx_length) {
        transport_ops->dereg_mr(ctx->tx.mr);
        zlibc_free(ctx->tx.addr);
        ctx->tx_length = 0;
    }

    /* create a new buffer & MR */
    ctx->tx.addr = rdmaMemoryAlloc(length);
    ctx->tx_length = length;
    ctx->tx.mr = transport_ops->reg_mr(ctx->domain, ctx->tx.addr, length, access);
    if (!ctx->tx.mr) {
        serverRdmaError(server.neterr, "RDMA: reg send mr failed");
        serverLog(LL_WARNING, "RDMA: FATAL error, recv corrupted cmd");
        zlibc_free(ctx->tx.addr);
        ctx->tx.addr = NULL;
        ctx->tx_length = 0;
        return C_ERR;
    }

    return C_OK;
}

static int rdmaSendCommand(RdmaContext *ctx, rdmaTransportEP *ep, ValkeyRdmaCmd *cmd) {
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
    ret = transport_ops->post_send(ep, _cmd, sizeof(ValkeyRdmaCmd),
                                   ctx->cmd_mr, (uint64_t)(uintptr_t)_cmd, 1);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: post send failed: %d", ret);
        return C_ERR;
    }

    return C_OK;
}

static int connRdmaRegisterRx(RdmaContext *ctx, rdmaTransportEP *ep) {
    ValkeyRdmaCmd cmd = {0};

    cmd.memory.opcode = htons(RegisterXferMemory);
    cmd.memory.addr = htonu64((uint64_t)(uintptr_t)ctx->rx.addr);
    cmd.memory.length = htonl(ctx->rx.length);
    cmd.memory.key = htonl(transport_ops->mr_rkey(ctx->rx.mr));

    ctx->rx.offset = 0;
    ctx->rx.pos = 0;

    return rdmaSendCommand(ctx, ep, &cmd);
}

static int connRdmaGetFeature(RdmaContext *ctx, rdmaTransportEP *ep, ValkeyRdmaCmd *cmd) {
    ValkeyRdmaCmd _cmd = {0};

    _cmd.feature.opcode = htons(GetServerFeature);
    _cmd.feature.select = cmd->feature.select;
    _cmd.feature.features = htonu64(0); /* currently no feature support */

    return rdmaSendCommand(ctx, ep, &_cmd);
}

static int connRdmaSetFeature(RdmaContext *ctx, rdmaTransportEP *ep, ValkeyRdmaCmd *cmd) {
    UNUSED(ctx);
    UNUSED(ep);

    /* currently no feature support */
    if (ntohu64(cmd->feature.features)) return C_ERR;

    return C_OK;
}

static int rdmaHandleEstablished(rdmaTransportEP *ep) {
    RdmaContext *ctx = transport_ops->get_ep_context(ep);

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

static int rdmaHandleDisconnect(aeEventLoop *el, rdmaTransportEP *ep) {
    RdmaContext *ctx = transport_ops->get_ep_context(ep);
    connection *conn = ctx->conn;
    rdma_connection *rdma_conn = (rdma_connection *)conn;

    rdmaDelKeepalive(el, ctx);
    conn->state = CONN_STATE_CLOSED;

    /* we can't close connection now, let's mark this connection as closed state */
    listAddNodeTail(pending_list, conn);
    rdma_conn->pending_list_node = listLast(pending_list);

    return C_OK;
}

static int connRdmaHandleRecv(RdmaContext *ctx, rdmaTransportEP *ep, ValkeyRdmaCmd *cmd, uint32_t byte_len) {
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

static int connRdmaHandleRecvImm(RdmaContext *ctx, rdmaTransportEP *ep, ValkeyRdmaCmd *cmd, uint32_t byte_len) {
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
    rdmaTransportEP *ep = rdma_conn->ep;
    RdmaContext *ctx = transport_ops->get_ep_context(ep);
    rdmaTransportWC wc = {0};
    ValkeyRdmaCmd *cmd;
    int ret;

    ret = transport_ops->get_cq_event(ctx->cq);
    if (ret < 0) {
        serverLog(LL_WARNING, "RDMA: get CQ event error");
        return C_ERR;
    } else if (ret == 0) {
        return C_OK;
    }

    transport_ops->ack_cq_event(ctx->cq);

pollcq:
    ret = transport_ops->poll_cq(ctx->cq, &wc);
    if (ret < 0) {
        serverLog(LL_WARNING, "RDMA: poll recv CQ error");
        return C_ERR;
    } else if (ret == 0) {
        return C_OK;
    }

    if (wc.status != 0) {
        if (rdma_conn->c.state == CONN_STATE_CONNECTED) {
            serverLog(LL_WARNING, "RDMA: CQ handle error status: %s[0x%x], opcode : 0x%x",
                      transport_ops->wc_status_str(wc.status), wc.status, wc.opcode);
        }
        return C_ERR;
    }

    switch (wc.opcode) {
    case RDMA_TRANSPORT_WC_RECV:
        cmd = (ValkeyRdmaCmd *)(uintptr_t)wc.wr_id;
        if (connRdmaHandleRecv(ctx, ep, cmd, wc.byte_len) == C_ERR) {
            return C_ERR;
        }
        break;

    case RDMA_TRANSPORT_WC_RECV_RDMA_WITH_IMM:
        cmd = (ValkeyRdmaCmd *)(uintptr_t)wc.wr_id;
        if (connRdmaHandleRecvImm(ctx, ep, cmd, wc.imm_data) == C_ERR) {
            rdma_conn->c.state = CONN_STATE_ERROR;
            return C_ERR;
        }

        break;
    case RDMA_TRANSPORT_WC_RDMA_WRITE:
        if (connRdmaHandleWrite(ctx, wc.byte_len) == C_ERR) {
            return C_ERR;
        }

        break;

    case RDMA_TRANSPORT_WC_SEND:
        cmd = (ValkeyRdmaCmd *)(uintptr_t)wc.wr_id;
        if (connRdmaHandleSend(cmd) == C_ERR) {
            return C_ERR;
        }

        break;

    default: serverLog(LL_WARNING, "RDMA: unexpected opcode 0x[%x]", wc.opcode); return C_ERR;
    }

    goto pollcq;
}

static int connRdmaAccept(connection *conn, ConnectionCallbackFunc accept_handler) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    rdmaTransportEP *ep = rdma_conn->ep;
    RdmaContext *ctx = transport_ops->get_ep_context(ep);
    int max_sge;
    int ret = C_OK;

    if (conn->state != CONN_STATE_ACCEPTING) return C_ERR;

    conn->state = CONN_STATE_CONNECTED;

    connIncrRefs(conn);
    if (!callHandler(conn, accept_handler)) ret = C_ERR;
    connDecrRefs(conn);

    max_sge = transport_ops->query_device_max_sge(ep);
    if (max_sge < 0) {
        serverLog(LL_WARNING, "RDMA: query device failed");
        return C_ERR;
    }

    conn->iovcnt = min(max_sge, IOV_MAX);
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
    /* The comp channel fd should be always non block */
    connNonBlock(&rdma_conn->c);

    return (connection *)rdma_conn;
}

static void connRdmaEventHandler(struct aeEventLoop *el, int fd, void *clientData, int mask) {
    rdma_connection *rdma_conn = (rdma_connection *)clientData;
    connection *conn = &rdma_conn->c;
    rdmaTransportEP *ep = rdma_conn->ep;
    RdmaContext *ctx = transport_ops->get_ep_context(ep);
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

    /* RDMA comp channel has no POLLOUT event, try to send remaining buffer */
    if (!(rdma_conn->flags & RDMA_CONN_FLAG_POSTPONE_UPDATE_STATE) && ctx->tx.offset < ctx->tx.length && conn->write_handler) {
        callHandler(conn, conn->write_handler);
    }
}

static long long rdmaKeepaliveTimeProc(struct aeEventLoop *el, long long id, void *clientData) {
    rdmaTransportEP *ep = clientData;
    RdmaContext *ctx = transport_ops->get_ep_context(ep);
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

static int rdmaHandleConnect(aeEventLoop *el, char *err, rdmaTransportCMEventData *ev_data,
                              char *ip, size_t ip_len, int *port) {
    int ret = C_OK;
    rdmaTransportEP *ep = ev_data->new_ep;
    struct sockaddr_storage caddr;
    RdmaContext *ctx = NULL;
    rdmaTransportConnParam conn_param = {
        .responder_resources = 1,
        .initiator_depth = 1,
        .retry_count = 5,
        .rnr_retry_count = 0,
    };

    transport_ops->get_peer_addr_from_request(ev_data, &caddr);
    if (caddr.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&caddr;
        if (ip) inet_ntop(AF_INET, (void *)&(s->sin_addr), ip, ip_len);
        if (port) *port = ntohs(s->sin_port);
    } else {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&caddr;
        if (ip) inet_ntop(AF_INET6, (void *)&(s->sin6_addr), ip, ip_len);
        if (port) *port = ntohs(s->sin6_port);
    }

    ctx = zcalloc(sizeof(RdmaContext));
    ctx->ip = zstrdup(ip);
    ctx->port = *port;
    ctx->keepalive_te = aeCreateTimeEvent(el, VALKEY_RDMA_KEEPALIVE_MS, rdmaKeepaliveTimeProc, ep, NULL);
    if (ctx->keepalive_te == AE_ERR) {
        return C_ERR;
    }

    transport_ops->set_ep_context(ep, ctx);
    if (rdmaCreateResource(ctx, ep) == C_ERR) {
        goto reject;
    }

    ret = transport_ops->accept(ep, &conn_param);
    if (ret) {
        serverRdmaError(err, "RDMA: accept failed");
        goto free_rdma;
    }

    return C_OK;

free_rdma:
    rdmaReleaseResource(ctx);
reject:
    /* reject connect request if hitting error */
    transport_ops->reject(ep);

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
 * rdmaAccept, actually it works as cm-event handler for listen cm_id.
 * accept a connection logic works in two steps:
 * 1, handle RDMA_CM_EVENT_CONNECT_REQUEST and return CM fd on success
 * 2, handle RDMA_CM_EVENT_ESTABLISHED and return C_OK on success
 */
static int
rdmaAccept(aeEventLoop *el, connListener *listener, char *err, int fd, char *ip, size_t ip_len, int *port, void **priv) {
    rdmaTransportCMEventData ev_data;
    int ret = C_OK;
    rdma_listener *rdma_listener;

    rdma_listener = rdmaFdToListener(listener, fd);
    if (!rdma_listener) {
        serverPanic("RDMA: unexpected listen file descriptor");
    }

    ret = transport_ops->get_cm_event(rdma_listener->eq, &ev_data);
    if (ret < 0) {
        serverLog(LL_WARNING, "RDMA: listen channel get cm event failed, %s", strerror(errno));
        return ANET_ERR;
    } else if (ret == 0) {
        return ANET_OK;
    }

    switch (ev_data.event) {
    case RDMA_TRANSPORT_CM_CONNECT_REQUEST:
        ret = rdmaHandleConnect(el, err, &ev_data, ip, ip_len, port);
        if (ret == C_OK) {
            RdmaContext *ctx = transport_ops->get_ep_context(ev_data.new_ep);
            *priv = ev_data.new_ep;
            ret = transport_ops->get_cq_fd(ctx->cq);
        }
        break;

    case RDMA_TRANSPORT_CM_ESTABLISHED:
        ret = rdmaHandleEstablished(ev_data.new_ep);
        break;

    case RDMA_TRANSPORT_CM_DISCONNECTED:
        rdmaHandleDisconnect(el, ev_data.new_ep);
        ret = C_OK;
        break;

    case RDMA_TRANSPORT_CM_IGNORED:
    default: serverLog(LL_NOTICE, "RDMA: listen channel ignore event"); break;
    }

    if (transport_ops->ack_cm_event(rdma_listener->eq)) {
        serverLog(LL_WARNING, "ack cm event failed\n");
        return ANET_ERR;
    }

    return ret;
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

static int rdmaConnect(RdmaContext *ctx, rdmaTransportEP *ep) {
    rdmaTransportConnParam conn_param = {0};

    if (rdmaCreateResource(ctx, ep) == C_ERR) {
        return C_ERR;
    }

    /* rdma connect with param */
    conn_param.responder_resources = 1;
    conn_param.initiator_depth = 1;
    conn_param.retry_count = 7;
    conn_param.rnr_retry_count = 7;
    if (transport_ops->connect(ep, &conn_param)) {
        return C_ERR;
    }

    int cq_fd = transport_ops->get_cq_fd(ctx->cq);
    anetNonBlock(NULL, cq_fd);
    anetCloexec(cq_fd);

    return C_OK;
}

/* TODO: rdmaAccept also deals with RDMA event, server side has different logic with client side, maybe we can merge
 * this CM logic in future */
static void rdmaCMeventHandler(struct aeEventLoop *el, int fd, void *clientData, int mask) {
    rdma_connection *rdma_conn = (rdma_connection *)clientData;
    connection *conn = &rdma_conn->c;
    rdmaTransportEP *ep = rdma_conn->ep;
    RdmaContext *ctx = transport_ops->get_ep_context(ep);
    rdmaTransportCMEventData ev_data;
    int ret;

    UNUSED(el);
    UNUSED(fd);
    UNUSED(mask);

    ret = transport_ops->get_cm_event(ctx->cm_channel, &ev_data);
    if (ret <= 0) {
        if (ret < 0) {
            serverLog(LL_WARNING, "RDMA: client channel get cm event failed, %s", strerror(errno));
        }
        return;
    }

    switch (ev_data.event) {
    case RDMA_TRANSPORT_CM_ADDR_RESOLVED:
        /* resolve route at most 100ms */
        if (transport_ops->resolve_route(ep, 100)) {
            rdmaConnectFailed(rdma_conn);
        }
        break;

    case RDMA_TRANSPORT_CM_ROUTE_RESOLVED:
        if (rdmaConnect(ctx, ep) == C_ERR) {
            rdmaConnectFailed(rdma_conn);
        }
        break;

    case RDMA_TRANSPORT_CM_ESTABLISHED:
        rdmaHandleEstablished(ep);
        conn->state = CONN_STATE_CONNECTED;
        conn->fd = transport_ops->get_cq_fd(ctx->cq);
        if (conn->conn_handler) {
            callHandler(conn, conn->conn_handler);
        }
        break;

    case RDMA_TRANSPORT_CM_REJECTED:
    case RDMA_TRANSPORT_CM_ERROR: rdmaConnectFailed(rdma_conn); break;

    case RDMA_TRANSPORT_CM_DISCONNECTED: rdmaHandleDisconnect(el, ep); break;

    case RDMA_TRANSPORT_CM_IGNORED:
    default: serverLog(LL_NOTICE, "RDMA: client channel ignore event");
    }

    if (transport_ops->ack_cm_event(ctx->cm_channel)) {
        serverLog(LL_NOTICE, "RDMA: ack cm event failed\n");
    }

    /* connection error or closed by remote peer */
    if (conn->state == CONN_STATE_ERROR) {
        callHandler(conn, conn->conn_handler);
    }
}

/* free resource during connection close */
static int rdmaResolveAddr(rdma_connection *rdma_conn, const char *addr, int port, const char *src_addr) {
    struct addrinfo hints, *servinfo = NULL, *p = NULL;
    rdmaTransportEQ *cm_channel = NULL;
    rdmaTransportEP *ep = NULL;
    RdmaContext *ctx = NULL;
    struct sockaddr_storage saddr;
    char _port[6]; /* strlen("65535") */
    int availableAddrs = 0;
    int ret = C_ERR;

    UNUSED(src_addr);
    ctx = zcalloc(sizeof(RdmaContext));
    if (!ctx) {
        serverLog(LL_WARNING, "RDMA: Out of memory");
        goto out;
    }

    cm_channel = transport_ops->create_event_channel();
    if (!cm_channel) {
        serverLog(LL_WARNING, "RDMA: create event channel failed");
        goto out;
    }
    ctx->cm_channel = cm_channel;

    ep = transport_ops->create_client_ep(cm_channel);
    if (!ep) {
        serverLog(LL_WARNING, "RDMA: create endpoint failed");
        goto out;
    }
    transport_ops->set_ep_context(ep, ctx);
    rdma_conn->ep = ep;

    int eq_fd = transport_ops->get_eq_fd(cm_channel);
    if (anetNonBlock(NULL, eq_fd) != C_OK) {
        serverLog(LL_WARNING, "RDMA: set cm channel fd non-block failed");
        goto out;
    }

    snprintf(_port, 6, "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(addr, _port, &hints, &servinfo)) {
        hints.ai_family = AF_INET6;
        if (getaddrinfo(addr, _port, &hints, &servinfo)) {
            serverLog(LL_WARNING, "RDMA: bad server addr info");
            goto out;
        }
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        if (p->ai_family == PF_INET) {
            memcpy(&saddr, p->ai_addr, sizeof(struct sockaddr_in));
            ((struct sockaddr_in *)&saddr)->sin_port = htons(port);
        } else if (p->ai_family == PF_INET6) {
            memcpy(&saddr, p->ai_addr, sizeof(struct sockaddr_in6));
            ((struct sockaddr_in6 *)&saddr)->sin6_port = htons(port);
        } else {
            serverLog(LL_WARNING, "RDMA: Unsupported family");
            goto out;
        }

        /* resolve addr at most 100ms */
        if (transport_ops->resolve_addr(ep, (struct sockaddr *)&saddr, 100)) {
            continue;
        }
        availableAddrs++;
    }

    if (!availableAddrs) {
        serverLog(LL_WARNING, "RDMA: server addr not available");
        goto out;
    }

    ret = C_OK;

out:
    if (servinfo) {
        freeaddrinfo(servinfo);
    }

    return ret;
}

static int connRdmaWait(connection *conn, long start, long timeout) {
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
    rdmaTransportEP *ep;
    RdmaContext *ctx;

    /* RDMA does not support multipath, and there is no outgoing RDMA connection at the current stage */
    assert(!multipath);

    if (rdmaResolveAddr(rdma_conn, addr, port, src_addr) == C_ERR) {
        return C_ERR;
    }

    ep = rdma_conn->ep;
    ctx = transport_ops->get_ep_context(ep);
    int eq_fd = transport_ops->get_eq_fd(ctx->cm_channel);
    if (aeCreateFileEvent(server.el, eq_fd, AE_READABLE, rdmaCMeventHandler, conn) == AE_ERR) {
        return C_ERR;
    }

    conn->conn_handler = connect_handler;

    return C_OK;
}

static int connRdmaBlockingConnect(connection *conn, const char *addr, int port, long long timeout) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    rdmaTransportEP *ep;
    RdmaContext *ctx;
    long long start = mstime();

    if (rdmaResolveAddr(rdma_conn, addr, port, NULL) == C_ERR) {
        return C_ERR;
    }

    ep = rdma_conn->ep;
    ctx = transport_ops->get_ep_context(ep);
    int eq_fd = transport_ops->get_eq_fd(ctx->cm_channel);
    if (aeCreateFileEvent(server.el, eq_fd, AE_READABLE, rdmaCMeventHandler, conn) == AE_ERR) {
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
    rdmaTransportEP *ep = rdma_conn->ep;
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

    ctx = transport_ops->get_ep_context(ep);
    rdmaDelKeepalive(server.el, ctx);
    transport_ops->disconnect(ep);

    /* poll all CQ before close */
    connRdmaHandleCq(rdma_conn);
    rdmaReleaseResource(ctx);
    transport_ops->destroy_ep(ep);

    if (ctx->cm_channel) {
        int eq_fd = transport_ops->get_eq_fd(ctx->cm_channel);
        aeDeleteFileEvent(server.el, eq_fd, AE_READABLE);
        transport_ops->destroy_event_channel(ctx->cm_channel);
    }

    rdma_conn->ep = NULL;
    zfree(ctx);
    zfree(conn);
}

static size_t connRdmaSend(connection *conn, const void *data, size_t data_len) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    rdmaTransportEP *ep = rdma_conn->ep;
    RdmaContext *ctx = transport_ops->get_ep_context(ep);
    uint32_t off = ctx->tx.offset;
    char *addr = ctx->tx.addr + off;
    char *remote_addr = ctx->tx_addr + ctx->tx.offset;
    int signaled;
    int ret;

    if (connRdmaAllowCommand()) {
        return C_ERR;
    }

    memcpy(addr, data, data_len);

    signaled = (++ctx->tx_ops % (VALKEY_RDMA_MAX_WQE / 2)) ? 0 : 1;
    ret = transport_ops->post_rdma_write_imm(ep, addr, data_len, ctx->tx.mr,
                                              (uint64_t)(uintptr_t)remote_addr,
                                              ctx->tx_key, (uint32_t)data_len,
                                              0, signaled);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: post send failed: %d", ret);
        conn->state = CONN_STATE_ERROR;
        return C_ERR;
    }

    ctx->tx.offset += data_len;

    return data_len;
}

static int connRdmaWrite(connection *conn, const void *data, size_t data_len) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    rdmaTransportEP *ep = rdma_conn->ep;
    RdmaContext *ctx = transport_ops->get_ep_context(ep);
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
    rdmaTransportEP *ep = rdma_conn->ep;
    RdmaContext *ctx = transport_ops->get_ep_context(ep);

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
    rdmaTransportEP *ep = rdma_conn->ep;
    RdmaContext *ctx = transport_ops->get_ep_context(ep);
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
    rdmaTransportEP *ep = rdma_conn->ep;
    RdmaContext *ctx = transport_ops->get_ep_context(ep);
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
    rdmaTransportEP *ep = rdma_conn->ep;
    RdmaContext *ctx = transport_ops->get_ep_context(ep);
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
    int ret = ANET_OK, rv;
    char _port[6]; /* strlen("65535") */
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage sock_addr;
    rdmaTransportEQ *listen_eq = NULL;
    rdmaTransportPEP *listen_pep = NULL;

    snprintf(_port, 6, "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = af;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; /* No effect if bindaddr != NULL */
    if (bindaddr && !strcmp("*", bindaddr)) bindaddr = NULL;

    if (af == AF_INET6 && bindaddr && !strcmp("::*", bindaddr)) bindaddr = NULL;

    if ((rv = getaddrinfo(bindaddr, _port, &hints, &servinfo)) != 0) {
        serverRdmaError(err, "RDMA: %s", gai_strerror(rv));
        return ANET_ERR;
    } else if (!servinfo) {
        serverRdmaError(err, "RDMA: get addr info failed");
        ret = ANET_ERR;
        goto end;
    }

    listen_eq = transport_ops->create_event_channel();
    if (!listen_eq) {
        serverLog(LL_WARNING, "RDMA: create event channel failed");
        goto error;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        memset(&sock_addr, 0, sizeof(sock_addr));
        if (p->ai_family == AF_INET6) {
            memcpy(&sock_addr, p->ai_addr, sizeof(struct sockaddr_in6));
            ((struct sockaddr_in6 *)&sock_addr)->sin6_family = AF_INET6;
            ((struct sockaddr_in6 *)&sock_addr)->sin6_port = htons(port);
        } else {
            memcpy(&sock_addr, p->ai_addr, sizeof(struct sockaddr_in));
            ((struct sockaddr_in *)&sock_addr)->sin_family = AF_INET;
            ((struct sockaddr_in *)&sock_addr)->sin_port = htons(port);
        }

        listen_pep = transport_ops->create_listen_ep(listen_eq, 1);
        if (!listen_pep) {
            serverRdmaError(err, "RDMA: create listen endpoint error");
            return ANET_ERR;
        }

        if (transport_ops->bind_listen(listen_pep, (struct sockaddr *)&sock_addr,
                                        sizeof(sock_addr))) {
            serverRdmaError(err, "RDMA: bind addr error");
            goto error;
        }

        if (transport_ops->listen_ep(listen_pep, 0)) {
            serverRdmaError(err, "RDMA: listen addr error");
            goto error;
        }

        rdma_listener->pep = listen_pep;
        rdma_listener->eq = listen_eq;
        goto end;
    }

error:
    if (listen_pep) transport_ops->destroy_listen_ep(listen_pep);
    if (listen_eq) transport_ops->destroy_event_channel(listen_eq);
    ret = ANET_ERR;

end:
    freeaddrinfo(servinfo);
    return ret;
}

static int connRdmaIsLocal(connection *conn) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    struct sockaddr_storage laddr_storage, raddr_storage;
    struct sockaddr *laddr, *raddr;

    if (transport_ops->get_local_addr(rdma_conn->ep, &laddr_storage) < 0) return -1;
    if (transport_ops->get_peer_addr(rdma_conn->ep, &raddr_storage) < 0) return -1;

    laddr = (struct sockaddr *)&laddr_storage;
    raddr = (struct sockaddr *)&raddr_storage;

    if (laddr->sa_family == AF_INET) {
        struct sockaddr_in *lsa4 = (struct sockaddr_in *)laddr;
        struct sockaddr_in *rsa4 = (struct sockaddr_in *)raddr;
        return !memcmp(&lsa4->sin_addr, &rsa4->sin_addr, sizeof(lsa4->sin_addr));
    } else if (laddr->sa_family == AF_INET6) {
        struct sockaddr_in6 *lsa6 = (struct sockaddr_in6 *)laddr;
        struct sockaddr_in6 *rsa6 = (struct sockaddr_in6 *)raddr;
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

        int fd = transport_ops->get_eq_fd(rdma_listener->eq);
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
        transport_ops->destroy_listen_ep(rdma_listener->pep);
        transport_ops->destroy_event_channel(rdma_listener->eq);
    }

    listener->count = 0;
    zfree(rdma_listeners);
    rdma_listeners = NULL;
    rdma_config = NULL;
}

static int connRdmaAddr(connection *conn, char *ip, size_t ip_len, int *port, int remote) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    struct sockaddr_storage ss_buf;
    struct sockaddr_storage *ss = &ss_buf;
    struct sockaddr_in *sa4;
    struct sockaddr_in6 *sa6;

    int addr_ret;
    if (remote)
        addr_ret = transport_ops->get_peer_addr(rdma_conn->ep, ss);
    else
        addr_ret = transport_ops->get_local_addr(rdma_conn->ep, ss);

    if (addr_ret < 0) {
        goto error;
    }

    if (ss->ss_family == AF_INET) {
        sa4 = (struct sockaddr_in *)ss;
        if (ip) {
            if (inet_ntop(AF_INET, (void *)&(sa4->sin_addr), ip, ip_len) == NULL) {
                goto error;
            }
        }

        if (port) {
            *port = ntohs(sa4->sin_port);
        }
    } else if (ss->ss_family == AF_INET6) {
        sa6 = (struct sockaddr_in6 *)ss;
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

    if (transport_ops->init()) {
        serverLog(LL_WARNING, "RDMA: FATAL error, transport init failed");
    }

    serverLog(LL_NOTICE, "RDMA: using %s transport provider", transport_ops->name);
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
