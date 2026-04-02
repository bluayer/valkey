/* ==========================================================================
 * rdma_fabric.c - RDMA transport using libfabric FI_EP_RDM (native EFA).
 * --------------------------------------------------------------------------
 * Based on rdma.c by zhenwei pi <pizhenwei@bytedance.com>
 * Rewritten for FI_EP_RDM: shared endpoint, address vector, TCP handshake.
 * Wire protocol (ValkeyRdmaCmd 32-byte) is 100% compatible with ibverbs.
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
#include "server.h"
#include "serverassert.h"
#include "connection.h"

#if defined __linux__ && defined USE_RDMA
#if (USE_RDMA == 1 /* BUILD_YES */) || \
    ((USE_RDMA == 2 /* BUILD_MODULE */) && defined(BUILD_RDMA_MODULE) && (BUILD_RDMA_MODULE == 2))
#include "connhelpers.h"

#include <arpa/inet.h>
#include <stddef.h>
#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_tagged.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <netdb.h>
#include <sys/mman.h>

#ifndef container_of
#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))
#endif

/* ========================================================================
 * Wire protocol types — MUST match ibverbs rdma.c exactly (32 bytes each)
 * ======================================================================== */

typedef struct ValkeyRdmaFeature {
    uint16_t opcode;
    uint16_t select;
    uint8_t rsvd[20];
    uint64_t features;
} ValkeyRdmaFeature;

typedef struct ValkeyRdmaKeepalive {
    uint16_t opcode;
    uint8_t rsvd[30];
} ValkeyRdmaKeepalive;

typedef struct ValkeyRdmaMemory {
    uint16_t opcode;
    uint8_t rsvd[14];
    uint64_t addr;
    uint32_t length;
    uint32_t key;
} ValkeyRdmaMemory;

typedef union ValkeyRdmaCmd {
    ValkeyRdmaFeature feature;
    ValkeyRdmaKeepalive keepalive;
    ValkeyRdmaMemory memory;
} ValkeyRdmaCmd;

/* Operation context wrapper for FI_CONTEXT2 (EFA requires 64-byte context).
 * fi_ctx MUST be the first member — provider writes into it directly. */
typedef struct RdmaOpCtx {
    struct fi_context2 fi_ctx;  /* 64 bytes, provider-reserved */
    void *user_data;            /* ValkeyRdmaCmd* for recv/send, or NULL */
} RdmaOpCtx;

typedef enum ValkeyRdmaOpcode {
    GetServerFeature = 0,
    SetClientFeature = 1,
    Keepalive = 2,
    RegisterXferMemory = 3,
} ValkeyRdmaOpcode;

/* ========================================================================
 * Constants
 * ======================================================================== */

#define VALKEY_BUILD_BUG_ON(cond) ((void)sizeof(char[1 - 2 * !!(cond)]))
#define VALKEY_RDMA_MAX_WQE 1024
#define VALKEY_RDMA_DEFAULT_RX_SIZE (1024 * 1024)
#define VALKEY_RDMA_MIN_RX_SIZE (64 * 1024)
#define VALKEY_RDMA_MAX_RX_SIZE (16 * 1024 * 1024)
#define VALKEY_RDMA_SYNCIO_RES 10
#define VALKEY_RDMA_INVALID_OPCODE 0xffff
#define VALKEY_RDMA_KEEPALIVE_MS 3000

#define RDMA_CONN_FLAG_POSTPONE_UPDATE_STATE (1 << 0)

/* Max concurrent connections and recv pool sizing */
#define RDMA_MAX_CONNECTIONS 4096
#define RDMA_RECV_POOL_SIZE (VALKEY_RDMA_MAX_WQE * 8)

/* Libfabric endpoint name max size */
#define RDMA_MAX_EP_NAME 256

/* ========================================================================
 * Data structures
 * ======================================================================== */

typedef struct RdmaXfer {
    struct fid_mr *mr;
    void *mr_desc;
    char *addr;
    uint32_t length;
    uint32_t offset;
    uint32_t pos;
} RdmaXfer;

/* Per-connection RDMA context (buffers, MRs, transfer state) */
typedef struct RdmaContext {
    connection *conn;
    char *ip;
    int port;
    long long keepalive_te;
    fi_addr_t peer_addr;

    /* TX: RDMA write to remote rx buffer */
    RdmaXfer tx;
    char *tx_addr;       /* remote rx buffer address */
    uint64_t tx_key;     /* remote rx buffer rkey */
    uint32_t tx_length;  /* remote rx buffer length */
    uint32_t tx_offset;  /* remote rx buffer offset */
    uint32_t tx_ops;     /* send ops counter for signaling */

    /* RX: local buffer written by remote RDMA write */
    RdmaXfer rx;

    /* Per-connection send command buffers (VALKEY_RDMA_MAX_WQE entries) */
    ValkeyRdmaCmd *send_buf;
    RdmaOpCtx *send_ctx;        /* FI_CONTEXT2 wrappers for send ops */
    struct fid_mr *send_mr;
    void *send_mr_desc;

    /* Per-connection RMA write context (reusable) */
    RdmaOpCtx rma_ctx;
} RdmaContext;

typedef struct rdma_connection {
    connection c;          /* c.fd = eventfd */
    fi_addr_t peer_addr;
    int evfd;              /* eventfd for ae signaling */
    int flags;
    int last_errno;
    listNode *pending_list_node;
    RdmaContext *ctx;
} rdma_connection;

/* Global shared fabric resources (one per process) */
typedef struct RdmaGlobal {
    struct fi_info *fi;
    struct fid_fabric *fabric;
    struct fid_domain *domain;
    struct fid_ep *ep;
    struct fid_av *av;
    struct fid_cq *cq;
    int cq_fd;

    /* Global recv buffer pool */
    ValkeyRdmaCmd *recv_pool;
    RdmaOpCtx *recv_ctx;        /* FI_CONTEXT2 wrappers for recv ops */
    struct fid_mr *recv_pool_mr;
    void *recv_pool_mr_desc;
    int recv_pool_posted;

    /* Local endpoint name for address exchange */
    uint8_t local_name[RDMA_MAX_EP_NAME];
    size_t local_name_len;

    /* Connection lookup: fi_addr_t → rdma_connection* */
    rdma_connection *conn_map[RDMA_MAX_CONNECTIONS];

    int initialized;
} RdmaGlobal;

typedef struct rdma_listener {
    int tcp_fd;  /* TCP socket for handshake */
} rdma_listener;

/* ========================================================================
 * Global variables
 * ======================================================================== */

static list *pending_list;
static rdma_listener *rdma_listeners;
static serverRdmaContextConfig *rdma_config;
static size_t page_size;
static ConnectionType CT_RDMA;
static RdmaGlobal rdma_g;

/* ========================================================================
 * Forward declarations
 * ======================================================================== */

static void connRdmaEventHandler(struct aeEventLoop *el, int fd, void *clientData, int mask);
static void rdmaGlobalCqHandler(struct aeEventLoop *el, int fd, void *clientData, int mask);
static int rdmaProcessPendingData(void);

/* ========================================================================
 * Utility functions
 * ======================================================================== */

static void serverRdmaError(char *err, const char *fmt, ...) {
    va_list ap;
    if (!err) return;
    va_start(ap, fmt);
    vsnprintf(err, ANET_ERR_LEN, fmt, ap);
    va_end(ap);
}

static inline int connRdmaAllowCommand(void) {
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

/* Signal a connection's eventfd so ae picks it up */
static inline void rdmaSignalConnection(rdma_connection *rdma_conn) {
    uint64_t val = 1;
    int ret = write(rdma_conn->evfd, &val, sizeof(val));
    UNUSED(ret);
}

/* Drain eventfd (call from ae handler to clear readability) */
static inline void rdmaDrainEventfd(int evfd) {
    uint64_t val;
    int ret = read(evfd, &val, sizeof(val));
    UNUSED(ret);
}

/* Connection lookup by fi_addr_t */
static inline rdma_connection *rdmaLookupConnection(fi_addr_t addr) {
    if (addr < RDMA_MAX_CONNECTIONS) {
        return rdma_g.conn_map[addr];
    }
    return NULL;
}

static inline void rdmaRegisterConnection(fi_addr_t addr, rdma_connection *conn) {
    if (addr < RDMA_MAX_CONNECTIONS) {
        rdma_g.conn_map[addr] = conn;
    }
}

static inline void rdmaUnregisterConnection(fi_addr_t addr) {
    if (addr < RDMA_MAX_CONNECTIONS) {
        rdma_g.conn_map[addr] = NULL;
    }
}

/* ========================================================================
 * Memory management (page-aligned for RDMA MR, same as rdma.c)
 * ======================================================================== */

static void *rdmaMemoryAlloc(size_t size) {
    size_t real_size, aligned_size = (size + page_size - 1) & (~(page_size - 1));
    uint8_t *ptr;

    real_size = aligned_size + 2 * page_size;
    ptr = mmap(NULL, real_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        serverPanic("failed to allocate memory for RDMA region");
    }

    madvise(ptr, real_size, MADV_DONTDUMP);
    mprotect(ptr, page_size, PROT_NONE);
    mprotect(ptr + size + page_size, page_size, PROT_NONE);

    return ptr + page_size;
}

static void rdmaMemoryFree(void *ptr, size_t size) {
    uint8_t *real_ptr;
    size_t real_size, aligned_size;

    if (!ptr) return;

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

/* Forward declaration for error cleanup */
static void rdmaGlobalCleanup(void);

/* ========================================================================
 * Global fabric resource initialization (FI_EP_RDM)
 * ======================================================================== */

static int rdmaGlobalInit(const char *node, const char *service, uint64_t flags) {
    struct fi_info *hints, *fi;
    struct fi_cq_attr cq_attr = {0};
    struct fi_av_attr av_attr = {0};
    int ret, fd;

    if (rdma_g.initialized) return C_OK;

    hints = fi_allocinfo();
    if (!hints) return C_ERR;

    hints->caps = FI_MSG | FI_RMA | FI_RMA_EVENT | FI_SOURCE;
    hints->ep_attr->type = FI_EP_RDM;
    hints->mode = FI_CONTEXT2 | FI_RX_CQ_DATA;
    hints->domain_attr->mr_mode = FI_MR_LOCAL | FI_MR_VIRT_ADDR | FI_MR_ALLOCATED | FI_MR_PROV_KEY | FI_MR_ENDPOINT;
    hints->tx_attr->msg_order = FI_ORDER_SAS;
    hints->rx_attr->msg_order = FI_ORDER_SAS;

    ret = fi_getinfo(FI_VERSION(1, 6), node, service, flags, hints, &fi);
    fi_freeinfo(hints);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: fi_getinfo failed: %s", fi_strerror(-ret));
        goto err;
    }
    rdma_g.fi = fi;

    /* Respect provider's MR mode */
    if (fi->domain_attr->mr_mode & FI_MR_ENDPOINT) {
        serverLog(LL_VERBOSE, "RDMA: provider requires FI_MR_ENDPOINT");
    }

    /* Wire protocol only supports 32-bit rkey — reject providers with larger keys */
    if (fi->domain_attr->mr_key_size > 4) {
        serverLog(LL_WARNING, "RDMA: provider uses %zu-byte MR keys, "
                  "but wire protocol only supports 32-bit rkey",
                  fi->domain_attr->mr_key_size);
        goto err;
    }

    ret = fi_fabric(fi->fabric_attr, &rdma_g.fabric, NULL);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: fi_fabric failed: %s", fi_strerror(-ret));
        goto err;
    }

    ret = fi_domain(rdma_g.fabric, fi, &rdma_g.domain, NULL);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: fi_domain failed: %s", fi_strerror(-ret));
        goto err;
    }

    /* CQ with FD wait + FI_CQ_FORMAT_DATA for immediate data */
    cq_attr.size = fi->tx_attr->size + fi->rx_attr->size;
    if (cq_attr.size < (size_t)(VALKEY_RDMA_MAX_WQE * 4)) {
        cq_attr.size = VALKEY_RDMA_MAX_WQE * 4;
    }
    cq_attr.format = FI_CQ_FORMAT_DATA;
    cq_attr.wait_obj = FI_WAIT_FD;
    ret = fi_cq_open(rdma_g.domain, &cq_attr, &rdma_g.cq, NULL);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: fi_cq_open failed: %s", fi_strerror(-ret));
        goto err;
    }

    ret = fi_control(&rdma_g.cq->fid, FI_GETWAIT, &fd);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: FI_GETWAIT on CQ failed: %s", fi_strerror(-ret));
        goto err;
    }
    rdma_g.cq_fd = fd;
    anetNonBlock(NULL, fd);

    /* Address vector */
    av_attr.type = FI_AV_TABLE;
    av_attr.count = RDMA_MAX_CONNECTIONS;
    ret = fi_av_open(rdma_g.domain, &av_attr, &rdma_g.av, NULL);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: fi_av_open failed: %s", fi_strerror(-ret));
        goto err;
    }

    /* RDM endpoint */
    ret = fi_endpoint(rdma_g.domain, fi, &rdma_g.ep, NULL);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: fi_endpoint failed: %s", fi_strerror(-ret));
        goto err;
    }

    ret = fi_ep_bind(rdma_g.ep, &rdma_g.cq->fid, FI_TRANSMIT | FI_RECV);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: fi_ep_bind CQ failed: %s", fi_strerror(-ret));
        goto err;
    }

    ret = fi_ep_bind(rdma_g.ep, &rdma_g.av->fid, 0);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: fi_ep_bind AV failed: %s", fi_strerror(-ret));
        goto err;
    }

    ret = fi_enable(rdma_g.ep);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: fi_enable failed: %s", fi_strerror(-ret));
        goto err;
    }

    /* Get local endpoint name for address exchange */
    rdma_g.local_name_len = RDMA_MAX_EP_NAME;
    ret = fi_getname(&rdma_g.ep->fid, rdma_g.local_name, &rdma_g.local_name_len);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: fi_getname failed: %s", fi_strerror(-ret));
        goto err;
    }

    /* Allocate global recv buffer pool + FI_CONTEXT2 wrappers */
    size_t pool_bytes = sizeof(ValkeyRdmaCmd) * RDMA_RECV_POOL_SIZE;
    rdma_g.recv_pool = rdmaMemoryAlloc(pool_bytes);
    rdma_g.recv_ctx = zcalloc(sizeof(RdmaOpCtx) * RDMA_RECV_POOL_SIZE);

    uint64_t mr_access = FI_RECV | FI_SEND | FI_READ | FI_WRITE | FI_REMOTE_READ | FI_REMOTE_WRITE;
    ret = fi_mr_reg(rdma_g.domain, rdma_g.recv_pool, pool_bytes, mr_access, 0, 0, 0,
                    &rdma_g.recv_pool_mr, NULL);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: fi_mr_reg recv pool failed: %s", fi_strerror(-ret));
        goto err;
    }

    if (rdma_g.fi->domain_attr->mr_mode & FI_MR_ENDPOINT) {
        fi_mr_bind(rdma_g.recv_pool_mr, &rdma_g.ep->fid, 0);
        fi_mr_enable(rdma_g.recv_pool_mr);
    }

    rdma_g.recv_pool_mr_desc = fi_mr_desc(rdma_g.recv_pool_mr);

    /* Post initial recv buffers (context = RdmaOpCtx for FI_CONTEXT2) */
    for (int i = 0; i < RDMA_RECV_POOL_SIZE; i++) {
        ValkeyRdmaCmd *cmd = &rdma_g.recv_pool[i];
        RdmaOpCtx *opctx = &rdma_g.recv_ctx[i];
        opctx->user_data = cmd;
        struct iovec iov = {.iov_base = cmd, .iov_len = sizeof(ValkeyRdmaCmd)};
        struct fi_msg msg = {
            .msg_iov = &iov,
            .desc = &rdma_g.recv_pool_mr_desc,
            .iov_count = 1,
            .addr = FI_ADDR_UNSPEC,
            .context = opctx,
        };
        ret = fi_recvmsg(rdma_g.ep, &msg, 0);
        if (ret) {
            serverLog(LL_WARNING, "RDMA: initial fi_recvmsg failed: %s", fi_strerror(-ret));
            goto err;
        }
    }
    rdma_g.recv_pool_posted = RDMA_RECV_POOL_SIZE;

    /* Register CQ fd with ae for global polling */
    if (aeCreateFileEvent(server.el, rdma_g.cq_fd, AE_READABLE, rdmaGlobalCqHandler, NULL) == AE_ERR) {
        serverLog(LL_WARNING, "RDMA: failed to register CQ fd with event loop");
        goto err;
    }

    memset(rdma_g.conn_map, 0, sizeof(rdma_g.conn_map));
    rdma_g.initialized = 1;
    serverLog(LL_NOTICE, "RDMA: global fabric initialized (provider: %s)", fi->fabric_attr->prov_name);
    return C_OK;

err:
    rdmaGlobalCleanup();
    return C_ERR;
}

static void rdmaGlobalCleanup(void) {
    if (!rdma_g.initialized) return;

    if (rdma_g.cq_fd >= 0) {
        aeDeleteFileEvent(server.el, rdma_g.cq_fd, AE_READABLE);
    }

    if (rdma_g.recv_pool_mr) fi_close(&rdma_g.recv_pool_mr->fid);
    if (rdma_g.recv_pool) rdmaMemoryFree(rdma_g.recv_pool, sizeof(ValkeyRdmaCmd) * RDMA_RECV_POOL_SIZE);
    zfree(rdma_g.recv_ctx);

    if (rdma_g.ep) fi_close(&rdma_g.ep->fid);
    if (rdma_g.av) fi_close(&rdma_g.av->fid);
    if (rdma_g.cq) fi_close(&rdma_g.cq->fid);
    if (rdma_g.domain) fi_close(&rdma_g.domain->fid);
    if (rdma_g.fabric) fi_close(&rdma_g.fabric->fid);
    if (rdma_g.fi) fi_freeinfo(rdma_g.fi);

    memset(&rdma_g, 0, sizeof(rdma_g));
}

/* Re-post a recv buffer to the shared EP */
static int rdmaPostRecv(ValkeyRdmaCmd *cmd) {
    int idx = (int)(cmd - rdma_g.recv_pool);
    RdmaOpCtx *opctx = &rdma_g.recv_ctx[idx];
    opctx->user_data = cmd;
    struct iovec iov = {.iov_base = cmd, .iov_len = sizeof(ValkeyRdmaCmd)};
    struct fi_msg msg = {
        .msg_iov = &iov,
        .desc = &rdma_g.recv_pool_mr_desc,
        .iov_count = 1,
        .addr = FI_ADDR_UNSPEC,
        .context = opctx,
    };
    int ret = fi_recvmsg(rdma_g.ep, &msg, 0);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: fi_recvmsg failed: %s", fi_strerror(-ret));
        return C_ERR;
    }
    return C_OK;
}

/* ========================================================================
 * Per-connection buffer management
 * ======================================================================== */

static void rdmaDestroyConnBufs(RdmaContext *ctx) {
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

    if (ctx->send_mr) {
        fi_close(&ctx->send_mr->fid);
        ctx->send_mr = NULL;
    }
    rdmaMemoryFree(ctx->send_buf, sizeof(ValkeyRdmaCmd) * VALKEY_RDMA_MAX_WQE);
    ctx->send_buf = NULL;
    zfree(ctx->send_ctx);
    ctx->send_ctx = NULL;
}

static int rdmaSetupConnBufs(RdmaContext *ctx) {
    uint64_t access;
    size_t length;
    int ret, i;

    /* Send command buffers (per-connection) + FI_CONTEXT2 wrappers */
    length = sizeof(ValkeyRdmaCmd) * VALKEY_RDMA_MAX_WQE;
    ctx->send_buf = rdmaMemoryAlloc(length);
    ctx->send_ctx = zcalloc(sizeof(RdmaOpCtx) * VALKEY_RDMA_MAX_WQE);
    access = FI_SEND | FI_RECV;
    ret = fi_mr_reg(rdma_g.domain, ctx->send_buf, length, access, 0, 0, 0, &ctx->send_mr, NULL);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: fi_mr_reg send buf failed: %s", fi_strerror(-ret));
        goto err;
    }
    if (rdma_g.fi->domain_attr->mr_mode & FI_MR_ENDPOINT) {
        fi_mr_bind(ctx->send_mr, &rdma_g.ep->fid, 0);
        fi_mr_enable(ctx->send_mr);
    }
    ctx->send_mr_desc = fi_mr_desc(ctx->send_mr);

    for (i = 0; i < VALKEY_RDMA_MAX_WQE; i++) {
        ctx->send_buf[i].keepalive.opcode = VALKEY_RDMA_INVALID_OPCODE;
        ctx->send_ctx[i].user_data = &ctx->send_buf[i];
    }

    /* RX data buffer (remote writes here via RDMA) */
    access = FI_RECV | FI_SEND | FI_READ | FI_WRITE | FI_REMOTE_READ | FI_REMOTE_WRITE;
    length = rdma_config->rx_size;
    ctx->rx.addr = rdmaMemoryAlloc(length);
    ctx->rx.length = length;
    ret = fi_mr_reg(rdma_g.domain, ctx->rx.addr, length, access, 0, 0, 0, &ctx->rx.mr, NULL);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: fi_mr_reg rx buf failed: %s", fi_strerror(-ret));
        goto err;
    }
    if (rdma_g.fi->domain_attr->mr_mode & FI_MR_ENDPOINT) {
        fi_mr_bind(ctx->rx.mr, &rdma_g.ep->fid, 0);
        fi_mr_enable(ctx->rx.mr);
    }
    ctx->rx.mr_desc = fi_mr_desc(ctx->rx.mr);

    return C_OK;

err:
    rdmaDestroyConnBufs(ctx);
    return C_ERR;
}

static int rdmaAdjustSendbuf(RdmaContext *ctx, unsigned int length) {
    uint64_t access = FI_SEND | FI_RECV | FI_READ | FI_WRITE | FI_REMOTE_READ | FI_REMOTE_WRITE;
    int ret;

    if (length == ctx->tx_length) return C_OK;

    if (ctx->tx_length) {
        fi_close(&ctx->tx.mr->fid);
        rdmaMemoryFree(ctx->tx.addr, ctx->tx_length);
        ctx->tx_length = 0;
    }

    ctx->tx.addr = rdmaMemoryAlloc(length);
    ctx->tx_length = length;
    ret = fi_mr_reg(rdma_g.domain, ctx->tx.addr, length, access, 0, 0, 0, &ctx->tx.mr, NULL);
    if (ret) {
        serverRdmaError(server.neterr, "RDMA: reg send mr failed");
        serverLog(LL_WARNING, "RDMA: FATAL error, fi_mr_reg tx failed: %s", fi_strerror(-ret));
        rdmaMemoryFree(ctx->tx.addr, length);
        ctx->tx.addr = NULL;
        ctx->tx_length = 0;
        return C_ERR;
    }
    if (rdma_g.fi->domain_attr->mr_mode & FI_MR_ENDPOINT) {
        fi_mr_bind(ctx->tx.mr, &rdma_g.ep->fid, 0);
        fi_mr_enable(ctx->tx.mr);
    }
    ctx->tx.mr_desc = fi_mr_desc(ctx->tx.mr);

    return C_OK;
}

/* ========================================================================
 * TCP handshake for fi_getname address exchange
 * ======================================================================== */

/* Reliable read/write helpers for TCP handshake (handle partial transfers) */
static ssize_t tcpReadFull(int fd, void *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, (char *)buf + total, len - total);
        if (n <= 0) return -1;
        total += n;
    }
    return total;
}

static ssize_t tcpWriteFull(int fd, const void *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = write(fd, (const char *)buf + total, len - total);
        if (n <= 0) return -1;
        total += n;
    }
    return total;
}

/* Server side: read peer's EP name from TCP, insert into AV, send ours back.
 * Returns fi_addr_t or FI_ADDR_UNSPEC on error. */
static fi_addr_t rdmaTcpHandshakeServer(int tcp_fd) {
    uint8_t peer_name[RDMA_MAX_EP_NAME];
    uint32_t peer_name_len;
    fi_addr_t addr = FI_ADDR_UNSPEC;
    int ret;

    /* Read peer name length (4 bytes, network order) */
    if (tcpReadFull(tcp_fd, &peer_name_len, sizeof(peer_name_len)) < 0) return FI_ADDR_UNSPEC;
    peer_name_len = ntohl(peer_name_len);
    if (peer_name_len == 0 || peer_name_len > RDMA_MAX_EP_NAME) return FI_ADDR_UNSPEC;

    /* Read peer name */
    if (tcpReadFull(tcp_fd, peer_name, peer_name_len) < 0) return FI_ADDR_UNSPEC;

    /* Insert peer into AV */
    ret = fi_av_insert(rdma_g.av, peer_name, 1, &addr, 0, NULL);
    if (ret != 1) {
        serverLog(LL_WARNING, "RDMA: fi_av_insert failed: %s", fi_strerror(-ret));
        return FI_ADDR_UNSPEC;
    }

    /* Send our local name back */
    uint32_t local_len_net = htonl((uint32_t)rdma_g.local_name_len);
    if (tcpWriteFull(tcp_fd, &local_len_net, sizeof(local_len_net)) < 0) goto err_remove;
    if (tcpWriteFull(tcp_fd, rdma_g.local_name, rdma_g.local_name_len) < 0) goto err_remove;

    return addr;

err_remove:
    fi_av_remove(rdma_g.av, &addr, 1, 0);
    return FI_ADDR_UNSPEC;
}

/* Client side: send our EP name via TCP, read back server's, insert into AV. */
static fi_addr_t rdmaTcpHandshakeClient(int tcp_fd) {
    uint8_t peer_name[RDMA_MAX_EP_NAME];
    uint32_t peer_name_len;
    fi_addr_t addr = FI_ADDR_UNSPEC;
    int ret;

    /* Send our local name */
    uint32_t local_len_net = htonl((uint32_t)rdma_g.local_name_len);
    if (tcpWriteFull(tcp_fd, &local_len_net, sizeof(local_len_net)) < 0) return FI_ADDR_UNSPEC;
    if (tcpWriteFull(tcp_fd, rdma_g.local_name, rdma_g.local_name_len) < 0) return FI_ADDR_UNSPEC;

    /* Read peer name length */
    if (tcpReadFull(tcp_fd, &peer_name_len, sizeof(peer_name_len)) < 0) return FI_ADDR_UNSPEC;
    peer_name_len = ntohl(peer_name_len);
    if (peer_name_len == 0 || peer_name_len > RDMA_MAX_EP_NAME) return FI_ADDR_UNSPEC;

    /* Read peer name */
    if (tcpReadFull(tcp_fd, peer_name, peer_name_len) < 0) return FI_ADDR_UNSPEC;

    /* Insert into AV */
    ret = fi_av_insert(rdma_g.av, peer_name, 1, &addr, 0, NULL);
    if (ret != 1) {
        serverLog(LL_WARNING, "RDMA: fi_av_insert (client) failed: %s", fi_strerror(-ret));
        return FI_ADDR_UNSPEC;
    }

    return addr;
}

/* ========================================================================
 * Send/Recv command handling
 * ======================================================================== */

static int rdmaSendCommand(RdmaContext *ctx, ValkeyRdmaCmd *cmd) {
    ValkeyRdmaCmd *_cmd;
    int i, ret;

    /* Find unused send buffer slot */
    for (i = 0; i < VALKEY_RDMA_MAX_WQE; i++) {
        _cmd = &ctx->send_buf[i];
        if (_cmd->keepalive.opcode == VALKEY_RDMA_INVALID_OPCODE) break;
    }
    if (i == VALKEY_RDMA_MAX_WQE) {
        serverLog(LL_WARNING, "RDMA: no free send cmd slot");
        return C_ERR;
    }

    memcpy(_cmd, cmd, sizeof(ValkeyRdmaCmd));

    RdmaOpCtx *opctx = &ctx->send_ctx[i];
    opctx->user_data = _cmd;
    struct iovec iov = {.iov_base = _cmd, .iov_len = sizeof(ValkeyRdmaCmd)};
    struct fi_msg msg = {
        .msg_iov = &iov,
        .desc = &ctx->send_mr_desc,
        .iov_count = 1,
        .addr = ctx->peer_addr,
        .context = opctx,
    };

    ret = fi_sendmsg(rdma_g.ep, &msg, FI_COMPLETION);
    if (ret) {
        serverLog(LL_WARNING, "RDMA: fi_sendmsg failed: %s", fi_strerror(-ret));
        _cmd->keepalive.opcode = VALKEY_RDMA_INVALID_OPCODE;
        return C_ERR;
    }

    return C_OK;
}

static int connRdmaRegisterRx(RdmaContext *ctx) {
    ValkeyRdmaCmd cmd = {0};

    cmd.memory.opcode = htons(RegisterXferMemory);
    cmd.memory.addr = htonu64((uint64_t)(uintptr_t)ctx->rx.addr);
    cmd.memory.length = htonl(ctx->rx.length);
    cmd.memory.key = htonl(fi_mr_key(ctx->rx.mr));

    ctx->rx.offset = 0;
    ctx->rx.pos = 0;

    return rdmaSendCommand(ctx, &cmd);
}

static int connRdmaGetFeature(RdmaContext *ctx, ValkeyRdmaCmd *cmd) {
    ValkeyRdmaCmd _cmd = {0};

    _cmd.feature.opcode = htons(GetServerFeature);
    _cmd.feature.select = cmd->feature.select;
    _cmd.feature.features = htonu64(0); /* currently no feature support */

    return rdmaSendCommand(ctx, &_cmd);
}

static int connRdmaSetFeature(RdmaContext *ctx, ValkeyRdmaCmd *cmd) {
    UNUSED(ctx);

    /* currently no feature support */
    if (ntohu64(cmd->feature.features)) return C_ERR;

    return C_OK;
}

static int connRdmaHandleRecv(RdmaContext *ctx, ValkeyRdmaCmd *cmd, uint32_t byte_len) {
    if (unlikely(byte_len != sizeof(ValkeyRdmaCmd))) {
        serverLog(LL_WARNING, "RDMA: FATAL error, recv corrupted cmd");
        return C_ERR;
    }

    switch (ntohs(cmd->keepalive.opcode)) {
    case GetServerFeature: connRdmaGetFeature(ctx, cmd); break;
    case SetClientFeature: connRdmaSetFeature(ctx, cmd); break;
    case Keepalive: break;
    case RegisterXferMemory:
        ctx->tx_addr = (char *)(uintptr_t)ntohu64(cmd->memory.addr);
        ctx->tx.length = ntohl(cmd->memory.length);
        ctx->tx_key = ntohl(cmd->memory.key);
        ctx->tx.offset = 0;
        rdmaAdjustSendbuf(ctx, ctx->tx.length);
        break;
    default:
        serverLog(LL_WARNING, "RDMA: FATAL error, unknown cmd");
        return C_ERR;
    }

    return rdmaPostRecv(cmd);
}

static int connRdmaHandleSend(ValkeyRdmaCmd *cmd) {
    memset(cmd, 0x00, sizeof(*cmd));
    cmd->keepalive.opcode = VALKEY_RDMA_INVALID_OPCODE;
    return C_OK;
}

static int connRdmaHandleRecvImm(RdmaContext *ctx, ValkeyRdmaCmd *cmd, uint32_t byte_len) {
    assert(byte_len + ctx->rx.offset <= ctx->rx.length);
    ctx->rx.offset += byte_len;
    return rdmaPostRecv(cmd);
}

static int connRdmaHandleWrite(RdmaContext *ctx, uint32_t byte_len) {
    UNUSED(ctx);
    UNUSED(byte_len);
    return C_OK;
}

/* ========================================================================
 * Global CQ handler — polls shared CQ with fi_cq_readfrom, dispatches
 * ======================================================================== */

static void rdmaGlobalCqHandler(struct aeEventLoop *el, int fd, void *clientData, int mask) {
    struct fi_cq_data_entry cqe;
    fi_addr_t src_addr;
    rdma_connection *rdma_conn;
    RdmaContext *ctx;
    int ret;

    UNUSED(el);
    UNUSED(fd);
    UNUSED(clientData);
    UNUSED(mask);

    for (;;) {
        ret = fi_cq_readfrom(rdma_g.cq, &cqe, 1, &src_addr);
        if (ret == -FI_EAGAIN) break;
        if (ret == -FI_EAVAIL) {
            struct fi_cq_err_entry err_entry = {0};
            fi_cq_readerr(rdma_g.cq, &err_entry, 0);
            serverLog(LL_WARNING, "RDMA: CQ error: %s (prov: %s)",
                      fi_strerror(err_entry.err),
                      fi_cq_strerror(rdma_g.cq, err_entry.prov_errno, err_entry.err_data, NULL, 0));

            /* op_context is RdmaOpCtx* — cannot reliably map to a
             * specific connection, just log the error above. */
            continue;
        }
        if (ret < 0) {
            serverLog(LL_WARNING, "RDMA: fi_cq_readfrom failed: %s", fi_strerror(-ret));
            break;
        }

        /* Determine which connection this completion belongs to */
        if (cqe.flags & FI_RECV) {
            /* Received message — use src_addr to find connection */
            rdma_conn = rdmaLookupConnection(src_addr);
            if (!rdma_conn) {
                /* Unknown sender — could be stale, just re-post recv */
                if (cqe.buf) rdmaPostRecv((ValkeyRdmaCmd *)cqe.buf);
                continue;
            }
            ctx = rdma_conn->ctx;

            if (cqe.flags & FI_REMOTE_CQ_DATA) {
                /* RDMA write with immediate data (data transfer) */
                uint32_t imm = (uint32_t)cqe.data;
                if (connRdmaHandleRecvImm(ctx, (ValkeyRdmaCmd *)cqe.buf, imm) == C_ERR) {
                    rdma_conn->c.state = CONN_STATE_ERROR;
                }
            } else {
                /* Regular recv (control command) */
                if (connRdmaHandleRecv(ctx, (ValkeyRdmaCmd *)cqe.buf, cqe.len) == C_ERR) {
                    rdma_conn->c.state = CONN_STATE_ERROR;
                }
            }
            rdmaSignalConnection(rdma_conn);

        } else if (cqe.flags & FI_SEND) {
            /* Send completion — context is RdmaOpCtx wrapping the cmd */
            RdmaOpCtx *opctx = (RdmaOpCtx *)cqe.op_context;
            ValkeyRdmaCmd *cmd = (ValkeyRdmaCmd *)opctx->user_data;
            connRdmaHandleSend(cmd);

        } else if (cqe.flags & FI_RMA) {
            /* RDMA write completion */
            /* Nothing to do, write is fire-and-forget with periodic signaling */

        } else {
            serverLog(LL_WARNING, "RDMA: unexpected CQ flags: 0x%lx", (unsigned long)cqe.flags);
        }
    }
}

/* ========================================================================
 * Per-connection event handler (eventfd-based for ae integration)
 * ======================================================================== */

static inline void rdmaDelKeepalive(aeEventLoop *el, RdmaContext *ctx) {
    if (ctx->keepalive_te == AE_ERR) return;
    aeDeleteTimeEvent(el, ctx->keepalive_te);
    ctx->keepalive_te = AE_ERR;
}

static void connRdmaEventHandler(struct aeEventLoop *el, int fd, void *clientData, int mask) {
    rdma_connection *rdma_conn = (rdma_connection *)clientData;
    connection *conn = &rdma_conn->c;
    RdmaContext *ctx = rdma_conn->ctx;

    UNUSED(el);
    UNUSED(mask);

    if (fd >= 0) rdmaDrainEventfd(fd);

    if (!ctx) return;

    /* uplayer should read all */
    while (!(rdma_conn->flags & RDMA_CONN_FLAG_POSTPONE_UPDATE_STATE) && ctx->rx.pos < ctx->rx.offset) {
        if (conn->read_handler && (callHandler(conn, conn->read_handler) == C_ERR)) {
            return;
        }
    }

    /* recv buf is full, register a new RX buffer */
    if (ctx->rx.pos == ctx->rx.length) {
        connRdmaRegisterRx(ctx);
    }

    /* Try to send remaining buffer */
    if (!(rdma_conn->flags & RDMA_CONN_FLAG_POSTPONE_UPDATE_STATE) &&
        ctx->tx.offset < ctx->tx.length && conn->write_handler) {
        callHandler(conn, conn->write_handler);
    }
}

/* ========================================================================
 * Keepalive timer
 * ======================================================================== */

static long long rdmaKeepaliveTimeProc(struct aeEventLoop *el, long long id, void *clientData) {
    rdma_connection *rdma_conn = (rdma_connection *)clientData;
    RdmaContext *ctx = rdma_conn->ctx;
    connection *conn = &rdma_conn->c;
    ValkeyRdmaCmd cmd = {0};

    UNUSED(el);
    UNUSED(id);

    if (conn->state != CONN_STATE_CONNECTED) return AE_NOMORE;

    cmd.keepalive.opcode = htons(Keepalive);
    if (rdmaSendCommand(ctx, &cmd) != C_OK) return AE_NOMORE;

    return VALKEY_RDMA_KEEPALIVE_MS;
}

/* ========================================================================
 * Connection creation & accept
 * ======================================================================== */

static connection *connCreateRdma(void) {
    rdma_connection *rdma_conn = zcalloc(sizeof(rdma_connection));
    rdma_conn->c.type = &CT_RDMA;
    rdma_conn->c.fd = -1;
    rdma_conn->c.iovcnt = 1;
    rdma_conn->peer_addr = FI_ADDR_UNSPEC;
    rdma_conn->evfd = -1;
    return (connection *)rdma_conn;
}

static connection *connCreateAcceptedRdma(int fd, void *priv) {
    rdma_connection *rdma_conn = (rdma_connection *)connCreateRdma();
    rdma_conn->c.fd = fd;
    rdma_conn->c.state = CONN_STATE_ACCEPTING;
    rdma_conn->evfd = fd;

    /* priv is RdmaContext* from the TCP accept path */
    RdmaContext *ctx = (RdmaContext *)priv;
    rdma_conn->ctx = ctx;
    rdma_conn->peer_addr = ctx->peer_addr;
    ctx->conn = &rdma_conn->c;

    return (connection *)rdma_conn;
}

static int connRdmaAccept(connection *conn, ConnectionCallbackFunc accept_handler) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    RdmaContext *ctx = rdma_conn->ctx;
    int ret = C_OK;

    if (conn->state != CONN_STATE_ACCEPTING) return C_ERR;

    conn->state = CONN_STATE_CONNECTED;

    connIncrRefs(conn);
    if (!callHandler(conn, accept_handler)) ret = C_ERR;
    connDecrRefs(conn);

    conn->iovcnt = IOV_MAX;

    /* Register RX buffer with remote peer */
    connRdmaRegisterRx(ctx);

    return ret;
}

/*
 * TCP-based accept: read peer EP name, do AV insert, create connection context.
 * Returns eventfd (>= 0) on success, ANET_OK to skip, ANET_ERR on error.
 */
static int
rdmaAccept(aeEventLoop *el, connListener *listener, char *err, int fd, char *ip, size_t ip_len, int *port, void **priv) {
    struct sockaddr_storage caddr;
    socklen_t caddr_len = sizeof(caddr);
    int tcp_fd;
    fi_addr_t peer_addr;
    RdmaContext *ctx;
    int evfd;

    UNUSED(listener);

    tcp_fd = accept(fd, (struct sockaddr *)&caddr, &caddr_len);
    if (tcp_fd == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            serverRdmaError(err, "RDMA: TCP accept failed: %s", strerror(errno));
            return ANET_ERR;
        }
        return ANET_OK;
    }

    /* Extract client IP/port from TCP connection */
    if (caddr.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&caddr;
        if (ip) inet_ntop(AF_INET, &s->sin_addr, ip, ip_len);
        if (port) *port = ntohs(s->sin_port);
    } else {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&caddr;
        if (ip) inet_ntop(AF_INET6, &s->sin6_addr, ip, ip_len);
        if (port) *port = ntohs(s->sin6_port);
    }

    /* Perform synchronous TCP handshake to exchange EP names */
    peer_addr = rdmaTcpHandshakeServer(tcp_fd);
    close(tcp_fd);

    if (peer_addr == FI_ADDR_UNSPEC) {
        serverRdmaError(err, "RDMA: TCP handshake failed");
        return ANET_ERR;
    }

    /* Create eventfd for this connection */
    evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (evfd < 0) {
        serverRdmaError(err, "RDMA: eventfd creation failed");
        fi_av_remove(rdma_g.av, &peer_addr, 1, 0);
        return ANET_ERR;
    }

    /* Create per-connection context */
    ctx = zcalloc(sizeof(RdmaContext));
    ctx->ip = zstrdup(ip ? ip : "?");
    ctx->port = port ? *port : 0;
    ctx->peer_addr = peer_addr;
    ctx->keepalive_te = AE_ERR; /* will be set in connRdmaAcceptHandler with valid rdma_conn */

    if (rdmaSetupConnBufs(ctx) == C_ERR) {
        serverRdmaError(err, "RDMA: setup connection buffers failed");
        close(evfd);
        fi_av_remove(rdma_g.av, &peer_addr, 1, 0);
        zfree(ctx->ip);
        zfree(ctx);
        return ANET_ERR;
    }

    /* Register connection in lookup table */
    rdmaRegisterConnection(peer_addr, NULL); /* will be set in connCreateAcceptedRdma */

    *priv = ctx;
    return evfd;
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
            if (errno != EWOULDBLOCK)
                serverLog(LL_WARNING, "RDMA: Accepting client connection: %s", server.neterr);
            return;
        } else if (cfd == ANET_OK) {
            continue;
        }

        serverLog(LL_VERBOSE, "RDMA: Accepted %s:%d", cip, cport);
        connection *conn = connCreateAcceptedRdma(cfd, connpriv);
        rdma_connection *rdma_conn = (rdma_connection *)conn;

        /* Update keepalive timer with correct rdma_conn pointer */
        RdmaContext *ctx = rdma_conn->ctx;
        if (ctx->keepalive_te != AE_ERR) {
            aeDeleteTimeEvent(el, ctx->keepalive_te);
        }
        ctx->keepalive_te = aeCreateTimeEvent(el, VALKEY_RDMA_KEEPALIVE_MS, rdmaKeepaliveTimeProc, rdma_conn, NULL);

        /* Register in connection map */
        rdmaRegisterConnection(rdma_conn->peer_addr, rdma_conn);

        acceptCommonHandler(conn, flags, cip);
    }
}

/* ========================================================================
 * Read/Write handler registration
 * ======================================================================== */

static int connRdmaSetRwHandler(connection *conn) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    if (rdma_conn->flags & RDMA_CONN_FLAG_POSTPONE_UPDATE_STATE) return C_OK;

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

    if (conn->state != CONN_STATE_CONNECTED) return C_OK;

    conn->write_handler = func;
    if (barrier)
        conn->flags |= CONN_FLAG_WRITE_BARRIER;
    else
        conn->flags &= ~CONN_FLAG_WRITE_BARRIER;

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

/* ========================================================================
 * Connect (client-side)
 * ======================================================================== */

static int connRdmaConnect(connection *conn,
                           const char *addr,
                           int port,
                           const char *src_addr,
                           int multipath,
                           ConnectionCallbackFunc connect_handler) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    struct addrinfo hints, *servinfo = NULL, *p;
    char _port[6];
    int tcp_fd = -1;
    fi_addr_t peer_addr;
    RdmaContext *ctx;
    int evfd;

    assert(!multipath);
    UNUSED(src_addr);

    /* Ensure global fabric is initialized */
    if (rdmaGlobalInit(NULL, NULL, 0) != C_OK) {
        return C_ERR;
    }

    /* TCP connect to server for handshake */
    snprintf(_port, sizeof(_port), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(addr, _port, &hints, &servinfo)) {
        serverLog(LL_WARNING, "RDMA: getaddrinfo failed for %s:%d", addr, port);
        return C_ERR;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        tcp_fd = socket(p->ai_family, SOCK_STREAM, p->ai_protocol);
        if (tcp_fd == -1) continue;
        if (connect(tcp_fd, p->ai_addr, p->ai_addrlen) == 0) break;
        close(tcp_fd);
        tcp_fd = -1;
    }
    freeaddrinfo(servinfo);

    if (tcp_fd < 0) {
        serverLog(LL_WARNING, "RDMA: TCP connect to %s:%d failed", addr, port);
        return C_ERR;
    }

    /* Exchange EP names over TCP */
    peer_addr = rdmaTcpHandshakeClient(tcp_fd);
    close(tcp_fd);

    if (peer_addr == FI_ADDR_UNSPEC) {
        serverLog(LL_WARNING, "RDMA: handshake with %s:%d failed", addr, port);
        return C_ERR;
    }

    /* Create eventfd */
    evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (evfd < 0) {
        fi_av_remove(rdma_g.av, &peer_addr, 1, 0);
        return C_ERR;
    }

    /* Create context */
    ctx = zcalloc(sizeof(RdmaContext));
    ctx->ip = zstrdup(addr);
    ctx->port = port;
    ctx->peer_addr = peer_addr;
    ctx->keepalive_te = AE_ERR;

    if (rdmaSetupConnBufs(ctx) == C_ERR) {
        close(evfd);
        fi_av_remove(rdma_g.av, &peer_addr, 1, 0);
        zfree(ctx->ip);
        zfree(ctx);
        return C_ERR;
    }

    rdma_conn->ctx = ctx;
    rdma_conn->peer_addr = peer_addr;
    rdma_conn->evfd = evfd;
    conn->fd = evfd;
    ctx->conn = conn;

    rdmaRegisterConnection(peer_addr, rdma_conn);

    /* Transition to connected immediately (handshake is done) */
    conn->state = CONN_STATE_CONNECTED;
    conn->conn_handler = connect_handler;
    conn->iovcnt = IOV_MAX;

    /* Register RX buffer */
    connRdmaRegisterRx(ctx);

    /* Start keepalive */
    ctx->keepalive_te = aeCreateTimeEvent(server.el, VALKEY_RDMA_KEEPALIVE_MS, rdmaKeepaliveTimeProc, rdma_conn, NULL);

    if (aeCreateFileEvent(server.el, evfd, AE_READABLE, connRdmaEventHandler, conn) == AE_ERR) {
        rdmaDelKeepalive(server.el, ctx);
        rdmaUnregisterConnection(peer_addr);
        rdmaDestroyConnBufs(ctx);
        fi_av_remove(rdma_g.av, &peer_addr, 1, 0);
        close(evfd);
        zfree(ctx->ip);
        zfree(ctx);
        rdma_conn->ctx = NULL;
        conn->fd = -1;
        return C_ERR;
    }

    /* Call connect handler */
    if (conn->conn_handler) {
        callHandler(conn, conn->conn_handler);
    }

    return C_OK;
}

static int connRdmaBlockingConnect(connection *conn, const char *addr, int port, long long timeout) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    struct addrinfo hints, *servinfo = NULL, *p;
    char _port[6];
    int tcp_fd = -1;
    fi_addr_t peer_addr;
    RdmaContext *ctx;
    int evfd;
    long long start = mstime();

    UNUSED(timeout);

    if (rdmaGlobalInit(NULL, NULL, 0) != C_OK) return C_ERR;

    snprintf(_port, sizeof(_port), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(addr, _port, &hints, &servinfo)) return C_ERR;

    for (p = servinfo; p != NULL; p = p->ai_next) {
        tcp_fd = socket(p->ai_family, SOCK_STREAM, p->ai_protocol);
        if (tcp_fd == -1) continue;
        if (connect(tcp_fd, p->ai_addr, p->ai_addrlen) == 0) break;
        close(tcp_fd);
        tcp_fd = -1;
    }
    freeaddrinfo(servinfo);
    if (tcp_fd < 0) return C_ERR;

    peer_addr = rdmaTcpHandshakeClient(tcp_fd);
    close(tcp_fd);
    if (peer_addr == FI_ADDR_UNSPEC) return C_ERR;

    evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (evfd < 0) {
        fi_av_remove(rdma_g.av, &peer_addr, 1, 0);
        return C_ERR;
    }

    ctx = zcalloc(sizeof(RdmaContext));
    ctx->ip = zstrdup(addr);
    ctx->port = port;
    ctx->peer_addr = peer_addr;
    ctx->keepalive_te = AE_ERR;

    if (rdmaSetupConnBufs(ctx) == C_ERR) {
        close(evfd);
        fi_av_remove(rdma_g.av, &peer_addr, 1, 0);
        zfree(ctx->ip);
        zfree(ctx);
        return C_ERR;
    }

    rdma_conn->ctx = ctx;
    rdma_conn->peer_addr = peer_addr;
    rdma_conn->evfd = evfd;
    conn->fd = evfd;
    ctx->conn = conn;

    rdmaRegisterConnection(peer_addr, rdma_conn);

    conn->state = CONN_STATE_CONNECTED;
    conn->iovcnt = IOV_MAX;

    connRdmaRegisterRx(ctx);

    /* Wait for remote to send us their RX registration */
    while (!ctx->tx.mr && (mstime() - start) < timeout) {
        aeWait(rdma_g.cq_fd, AE_READABLE, VALKEY_RDMA_SYNCIO_RES);
        rdmaGlobalCqHandler(NULL, rdma_g.cq_fd, NULL, 0);
    }

    /* Start keepalive */
    ctx->keepalive_te = aeCreateTimeEvent(server.el, VALKEY_RDMA_KEEPALIVE_MS, rdmaKeepaliveTimeProc, rdma_conn, NULL);

    /* Register ae handler for incoming data */
    if (aeCreateFileEvent(server.el, evfd, AE_READABLE, connRdmaEventHandler, conn) == AE_ERR) {
        serverLog(LL_WARNING, "RDMA: failed to register eventfd with ae (blocking connect)");
    }

    return C_OK;
}

/* ========================================================================
 * Connection shutdown & close
 * ======================================================================== */

static void connRdmaShutdown(connection *conn) {
    UNUSED(conn);
}

static void connRdmaClose(connection *conn) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    RdmaContext *ctx = rdma_conn->ctx;

    if (conn->fd != -1) {
        aeDeleteFileEvent(server.el, conn->fd, AE_READABLE);
        conn->fd = -1;
    }

    if (connHasRefs(conn)) {
        conn->flags |= CONN_FLAG_CLOSE_SCHEDULED;
        return;
    }

    if (ctx) {
        rdmaDelKeepalive(server.el, ctx);

        /* Unregister from connection map */
        if (rdma_conn->peer_addr != FI_ADDR_UNSPEC) {
            rdmaUnregisterConnection(rdma_conn->peer_addr);
            fi_av_remove(rdma_g.av, &rdma_conn->peer_addr, 1, 0);
        }

        rdmaDestroyConnBufs(ctx);
        zfree(ctx->ip);
        zfree(ctx);
        rdma_conn->ctx = NULL;
    }

    if (rdma_conn->evfd >= 0) {
        close(rdma_conn->evfd);
        rdma_conn->evfd = -1;
    }

    if (rdma_conn->pending_list_node) {
        listDelNode(pending_list, rdma_conn->pending_list_node);
        rdma_conn->pending_list_node = NULL;
    }

    zfree(conn);
}

/* ========================================================================
 * I/O: Send (RDMA write with immediate), Write, Writev, Read
 * ======================================================================== */

static size_t connRdmaSend(connection *conn, const void *data, size_t data_len) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    RdmaContext *ctx = rdma_conn->ctx;
    uint32_t off = ctx->tx.offset;
    char *addr = ctx->tx.addr + off;
    int ret;

    if (connRdmaAllowCommand()) return C_ERR;

    memcpy(addr, data, data_len);

    struct iovec iov = {.iov_base = addr, .iov_len = data_len};
    struct fi_rma_iov rma_iov = {
        .addr = (uint64_t)(uintptr_t)(ctx->tx_addr + ctx->tx.offset),
        .len = data_len,
        .key = ctx->tx_key,
    };
    struct fi_msg_rma msg = {
        .msg_iov = &iov,
        .desc = &ctx->tx.mr_desc,
        .iov_count = 1,
        .addr = ctx->peer_addr,
        .rma_iov = &rma_iov,
        .rma_iov_count = 1,
        .context = &ctx->rma_ctx,
        .data = (uint64_t)htonl((uint32_t)data_len),
    };

    uint64_t flags = FI_REMOTE_CQ_DATA;
    if (++ctx->tx_ops % (VALKEY_RDMA_MAX_WQE / 2) == 0) {
        flags |= FI_COMPLETION;
    }

    ret = fi_writemsg(rdma_g.ep, &msg, flags);
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
    RdmaContext *ctx = rdma_conn->ctx;
    uint32_t towrite;

    if (connRdmaAllowRW(conn)) return C_ERR;

    assert(ctx->tx.offset <= ctx->tx.length);
    towrite = MIN(ctx->tx.length - ctx->tx.offset, data_len);
    if (!towrite) return 0;

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
    uint32_t toread = MIN(ctx->rx.offset - ctx->rx.pos, buf_len);

    assert(ctx->rx.pos + toread <= ctx->rx.length);
    memcpy(buf, ctx->rx.addr + ctx->rx.pos, toread);
    ctx->rx.pos += toread;

    return toread;
}

static int connRdmaRead(connection *conn, void *buf, size_t buf_len) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    RdmaContext *ctx = rdma_conn->ctx;

    if (connRdmaAllowRW(conn)) return C_ERR;

    if (ctx->rx.pos == ctx->rx.offset) return -1;

    assert(ctx->rx.pos < ctx->rx.offset);
    return rdmaRead(ctx, buf, buf_len);
}

/* ========================================================================
 * Synchronous I/O
 * ======================================================================== */

static int connRdmaWait(connection *conn, long start, long timeout) {
    long long remaining = timeout - (mstime() - start);
    long long wait = (remaining < VALKEY_RDMA_SYNCIO_RES) ? remaining : VALKEY_RDMA_SYNCIO_RES;

    if (remaining <= 0) {
        errno = ETIMEDOUT;
        return C_ERR;
    }

    aeWait(rdma_g.cq_fd, AE_READABLE, wait);
    rdmaGlobalCqHandler(NULL, rdma_g.cq_fd, NULL, 0);

    return C_OK;
}

static ssize_t connRdmaSyncWrite(connection *conn, char *ptr, ssize_t size, long long timeout) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    RdmaContext *ctx = rdma_conn->ctx;
    ssize_t nwritten = 0;
    long long start = mstime();
    uint32_t towrite;

    if (connRdmaAllowRW(conn)) return C_ERR;

    assert(ctx->tx.offset <= ctx->tx.length);
    if (ctx->tx.offset < ctx->tx.length) goto copy;

wait:
    if (connRdmaWait(conn, start, timeout) == C_ERR) return C_ERR;
    if (unlikely(!ctx->tx.mr)) goto wait;

copy:
    towrite = MIN(ctx->tx.length - ctx->tx.offset, size - nwritten);
    if (connRdmaSend(conn, ptr, towrite) == (size_t)C_ERR) return C_ERR;
    ptr += towrite;
    nwritten += towrite;

    if (nwritten < size) goto wait;

    return size;
}

static ssize_t connRdmaSyncRead(connection *conn, char *ptr, ssize_t size, long long timeout) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    RdmaContext *ctx = rdma_conn->ctx;
    ssize_t nread = 0;
    long long start = mstime();
    uint32_t toread;

    if (connRdmaAllowRW(conn)) return C_ERR;

    assert(ctx->rx.pos <= ctx->rx.offset);
    if (ctx->rx.pos < ctx->rx.offset) goto copy;

wait:
    if (connRdmaWait(conn, start, timeout) == C_ERR) return C_ERR;

copy:
    toread = rdmaRead(ctx, ptr, size - nread);
    ptr += toread;
    nread += toread;
    if (nread < size) goto wait;

    return size;
}

static ssize_t connRdmaSyncReadLine(connection *conn, char *ptr, ssize_t size, long long timeout) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    RdmaContext *ctx = rdma_conn->ctx;
    ssize_t nread = 0;
    long long start = mstime();
    uint32_t toread;
    char *c;
    char nl = 0;

    if (connRdmaAllowRW(conn)) return C_ERR;

    assert(ctx->rx.pos <= ctx->rx.offset);
    if (ctx->rx.pos < ctx->rx.offset) goto copy;

wait:
    if (connRdmaWait(conn, start, timeout) == C_ERR) return C_ERR;

copy:
    for (toread = 0; toread < ctx->rx.offset - ctx->rx.pos; toread++) {
        c = ctx->rx.addr + ctx->rx.pos + toread;
        if (*c == '\n') {
            *c = '\0';
            if (toread && *(c - 1) == '\r') *(c - 1) = '\0';
            nl = 1;
            break;
        }
    }

    toread = rdmaRead(ctx, ptr, MIN(toread + nl, size - nread));
    ptr += toread;
    nread += toread;
    if (nl) return nread;
    if (nread < size) goto wait;

    return size;
}

/* ========================================================================
 * Listener management (TCP socket for handshake)
 * ======================================================================== */

static int connRdmaGetType(void) {
    return CONN_TYPE_RDMA;
}

static int rdmaServer(char *err, int port, char *bindaddr, int af, rdma_listener *listener) {
    int ret = ANET_OK, rv, optval = 1;
    char _port[6];
    struct addrinfo hints, *servinfo, *p;
    int sfd = -1;

    snprintf(_port, sizeof(_port), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = af;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if (bindaddr && !strcmp("*", bindaddr)) bindaddr = NULL;
    if (af == AF_INET6 && bindaddr && !strcmp("::*", bindaddr)) bindaddr = NULL;

    if ((rv = getaddrinfo(bindaddr, _port, &hints, &servinfo)) != 0) {
        serverRdmaError(err, "RDMA: %s", gai_strerror(rv));
        return ANET_ERR;
    }
    if (!servinfo) {
        serverRdmaError(err, "RDMA: get addr info failed");
        return ANET_ERR;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        sfd = socket(p->ai_family, SOCK_STREAM, p->ai_protocol);
        if (sfd == -1) continue;

        setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
        if (af == AF_INET6) {
            int v6only = 1;
            setsockopt(sfd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
        }

        if (bind(sfd, p->ai_addr, p->ai_addrlen) == 0) break;
        close(sfd);
        sfd = -1;
    }
    freeaddrinfo(servinfo);

    if (sfd == -1) {
        serverRdmaError(err, "RDMA: TCP bind failed for %s:%d", bindaddr ? bindaddr : "*", port);
        return ANET_ERR;
    }

    if (listen(sfd, 511) == -1) {
        serverRdmaError(err, "RDMA: TCP listen failed");
        close(sfd);
        return ANET_ERR;
    }

    listener->tcp_fd = sfd;
    return ret;
}

int connRdmaListen(connListener *listener) {
    int j, ret;
    char **bindaddr = listener->bindaddr;
    int bindaddr_count = listener->bindaddr_count;
    int port = listener->port;
    char *default_bindaddr[2] = {"*", "-::*"};
    rdma_listener *rl;

    assert(server.proto_max_bulk_len <= 512ll * 1024 * 1024);

    if (listener->bindaddr_count == 0) {
        bindaddr_count = 2;
        bindaddr = default_bindaddr;
    }

    /* Initialize global fabric resources */
    if (rdmaGlobalInit(NULL, NULL, 0) != C_OK) {
        serverLog(LL_WARNING, "RDMA: failed to initialize global fabric");
        return C_ERR;
    }

    rdma_listeners = rl = zcalloc_num(bindaddr_count, sizeof(*rl));
    for (j = 0; j < bindaddr_count; j++) {
        char *addr = bindaddr[j];
        int optional = *addr == '-';

        if (optional) addr++;
        if (strchr(addr, ':'))
            ret = rdmaServer(server.neterr, port, addr, AF_INET6, rl);
        else
            ret = rdmaServer(server.neterr, port, addr, AF_INET, rl);

        if (ret == ANET_ERR) {
            serverLog(LL_WARNING, "RDMA: Could not create server for %s:%d: %s", addr, port, server.neterr);
            return C_ERR;
        }

        int fd = rl->tcp_fd;
        anetNonBlock(NULL, fd);
        anetCloexec(fd);
        listener->fd[listener->count++] = fd;
        rl++;
    }

    rdma_config = listener->priv;
    return C_OK;
}

static void connRdmaCloseListener(connListener *listener) {
    for (int i = 0; i < listener->count; i++) {
        if (listener->fd[i] == -1) continue;
        aeDeleteFileEvent(server.el, listener->fd[i], AE_READABLE);
        close(listener->fd[i]);
        listener->fd[i] = -1;
    }

    listener->count = 0;
    zfree(rdma_listeners);
    rdma_listeners = NULL;
    rdma_config = NULL;

    rdmaGlobalCleanup();
}

/* ========================================================================
 * Address & locality
 * ======================================================================== */

static int connRdmaAddr(connection *conn, char *ip, size_t ip_len, int *port, int remote) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    RdmaContext *ctx = rdma_conn->ctx;

    if (!ctx) goto error;

    if (remote) {
        if (ip && ctx->ip) {
            strncpy(ip, ctx->ip, ip_len);
            ip[ip_len - 1] = '\0';
        }
        if (port) *port = ctx->port;
    } else {
        /* Local address: use bind address from listener or "0.0.0.0" */
        if (ip) {
            strncpy(ip, "0.0.0.0", ip_len);
            ip[ip_len - 1] = '\0';
        }
        if (port) *port = 0;
    }
    return 0;

error:
    if (ip) {
        if (ip_len >= 2) { ip[0] = '?'; ip[1] = '\0'; }
        else if (ip_len == 1) ip[0] = '\0';
    }
    if (port) *port = 0;
    return -1;
}

static int connRdmaIsLocal(connection *conn) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    RdmaContext *ctx = rdma_conn->ctx;

    if (!ctx || !ctx->ip) return 0;

    /* Check if peer IP matches any local address */
    if (!strcmp(ctx->ip, "127.0.0.1") || !strcmp(ctx->ip, "::1")) return 1;

    return 0;
}

/* ========================================================================
 * Init, pending data, state management
 * ======================================================================== */

static void rdmaInit(void) {
    pending_list = listCreate();
    page_size = sysconf(_SC_PAGESIZE);

    VALKEY_BUILD_BUG_ON(sizeof(ValkeyRdmaFeature) != 32);
    VALKEY_BUILD_BUG_ON(sizeof(ValkeyRdmaKeepalive) != 32);
    VALKEY_BUILD_BUG_ON(sizeof(ValkeyRdmaMemory) != 32);
    VALKEY_BUILD_BUG_ON(sizeof(ValkeyRdmaCmd) != 32);

    memset(&rdma_g, 0, sizeof(rdma_g));
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

        if (conn->state == CONN_STATE_ERROR || conn->state == CONN_STATE_CLOSED) {
            listDelNode(pending_list, rdma_conn->pending_list_node);
            rdma_conn->pending_list_node = NULL;
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
    if (postpone)
        rdma_conn->flags |= RDMA_CONN_FLAG_POSTPONE_UPDATE_STATE;
    else
        rdma_conn->flags &= ~RDMA_CONN_FLAG_POSTPONE_UPDATE_STATE;
}

static void updateRdmaState(struct connection *conn) {
    rdma_connection *rdma_conn = (rdma_connection *)conn;
    connRdmaSetRwHandler(conn);
    connRdmaEventHandler(NULL, -1, rdma_conn, 0);
}

/* ========================================================================
 * ConnectionType vtable
 * ======================================================================== */

static ConnectionType CT_RDMA = {
    /* connection type */
    .get_type = connRdmaGetType,

    /* connection type initialize & finalize & configure */
    .init = rdmaInit,
    .cleanup = NULL,

    /* ae & accept & listen & error & address handler */
    .ae_handler = connRdmaEventHandler,
    .accept_handler = connRdmaAcceptHandler,
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

    if (strcmp(REDIS_BUILD_ID_RAW, serverBuildIdRaw())) {
        serverLog(LL_NOTICE, "Connection type %s was not built together with the valkey-server used.",
                  getConnectionTypeName(CONN_TYPE_RDMA));
        return VALKEYMODULE_ERR;
    }

    if (ValkeyModule_Init(ctx, getConnectionTypeName(CONN_TYPE_RDMA), 1, VALKEYMODULE_APIVER_1) == VALKEYMODULE_ERR)
        return VALKEYMODULE_ERR;

    if ((ValkeyModule_GetContextFlags(ctx) & VALKEYMODULE_CTX_FLAGS_SERVER_STARTUP) == 0) {
        serverLog(LL_NOTICE, "Connection type %s can be loaded only during bootup",
                  getConnectionTypeName(CONN_TYPE_RDMA));
        return VALKEYMODULE_ERR;
    }

    ValkeyModule_SetModuleOptions(ctx, VALKEYMODULE_OPTIONS_HANDLE_REPL_ASYNC_LOAD |
                                           VALKEYMODULE_OPTIONS_HANDLE_ATOMIC_SLOT_MIGRATION);

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
