/* ==========================================================================
 * rdma-test-fabric.c - test client for Valkey Over RDMA (libfabric backend)
 * --------------------------------------------------------------------------
 * Mirrors rdma-test.c but uses libfabric FI_EP_RDM + TCP handshake
 * instead of ibverbs + RDMA CM. For testing rdma_fabric.c server.
 *
 * Build (on EFA instance with libfabric installed):
 *   gcc -o rdma-test-fabric rdma-test-fabric.c -lfabric -lpthread
 *
 * Usage:
 *   ./rdma-test-fabric -h <server_ip> -p <rdma_port> [-t <threads>]
 * ==========================================================================
 */

#ifndef __linux__
#error "BUILD ERROR: RDMA is only supported on Linux"
#else

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <netdb.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_rma.h>

/* ========================================================================
 * Wire protocol (must match rdma.c / rdma_fabric.c exactly)
 * ======================================================================== */

typedef struct valkeyRdmaFeature {
    uint16_t opcode;
    uint16_t select;
    uint8_t rsvd[20];
    uint64_t features;
} valkeyRdmaFeature;

typedef struct valkeyRdmaKeepalive {
    uint16_t opcode;
    uint8_t rsvd[30];
} valkeyRdmaKeepalive;

/* Fabric backend: 64-bit key (matches rdma_fabric.c, NOT ibverbs rdma.c) */
typedef struct valkeyRdmaMemory {
    uint16_t opcode;
    uint8_t rsvd[6];
    uint64_t addr;
    uint64_t key;
    uint32_t length;
    uint32_t rsvd2;
} valkeyRdmaMemory;

typedef union valkeyRdmaCmd {
    valkeyRdmaFeature feature;
    valkeyRdmaKeepalive keepalive;
    valkeyRdmaMemory memory;
} valkeyRdmaCmd;

typedef enum valkeyRdmaOpcode {
    GetServerFeature = 0,
    SetClientFeature = 1,
    Keepalive = 2,
    RegisterXferMemory = 3,
} valkeyRdmaOpcode;

#define MAX_THREADS 32
#define UNUSED(x) (void)(x)
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define VALKEY_RDMA_MAX_WQE 1024
#define VALKEY_RDMA_DEFAULT_RX_LEN (1024 * 1024)
#define VALKEY_RDMA_INVALID_OPCODE 0xffff
#define RDMA_MAX_EP_NAME 256
#define RDMA_RECV_POOL_SIZE 256

/* FI_CONTEXT2 wrapper (EFA requires 64-byte context) */
typedef struct RdmaOpCtx {
    struct fi_context2 fi_ctx;  /* 64 bytes, provider-reserved */
    void *user_data;            /* back-pointer to valkeyRdmaCmd* */
} RdmaOpCtx;

#define rdmaFatal(msg)                                          \
    do {                                                        \
        fprintf(stderr, "%s:%d %s\n", __func__, __LINE__, msg); \
        assert(0);                                              \
    } while (0)

static inline long valkeyNowMs(void) {
    struct timeval tv;
    if (gettimeofday(&tv, NULL) < 0) return -1;
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/* ========================================================================
 * Per-client fabric context
 * ======================================================================== */

typedef struct FabricContext {
    struct fi_info *fi;
    struct fid_fabric *fabric;
    struct fid_domain *domain;
    struct fid_ep *ep;
    struct fid_av *av;
    struct fid_cq *cq;
    fi_addr_t peer_addr;
    bool connected;

    /* TX: RDMA write to remote RX buffer */
    char *tx_addr;       /* remote buffer address */
    uint32_t tx_length;  /* remote buffer length */
    uint32_t tx_offset;  /* current write offset */
    uint64_t tx_key;     /* remote MR key */
    char *send_buf;      /* local send data buffer */
    uint32_t send_length;
    uint32_t send_ops;
    struct fid_mr *send_mr;
    void *send_mr_desc;

    /* RX: local buffer written by remote RDMA write */
    uint32_t rx_offset;   /* bytes written by remote */
    char *recv_buf;
    uint32_t recv_length;
    uint32_t recv_offset; /* bytes consumed locally */
    struct fid_mr *recv_mr;
    void *recv_mr_desc;

    /* CMD: send/recv command buffers */
    valkeyRdmaCmd *cmd_buf;     /* [0..POOL-1] recv, [POOL..POOL+WQE-1] send */
    RdmaOpCtx *cmd_ctx;         /* FI_CONTEXT2 wrappers, same indexing as cmd_buf */
    RdmaOpCtx rma_ctx;          /* reusable context for RDMA writes */
    struct fid_mr *cmd_mr;
    void *cmd_mr_desc;
} FabricContext;

/* ========================================================================
 * Forward declarations
 * ======================================================================== */

static int connRdmaHandleCq(FabricContext *ctx);

/* ========================================================================
 * TCP helpers: safe partial read/write
 * ======================================================================== */

static ssize_t tcpReadFull(int fd, void *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, (char *)buf + total, len - total);
        if (n <= 0) return -1;
        total += n;
    }
    return (ssize_t)total;
}

static ssize_t tcpWriteFull(int fd, const void *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = write(fd, (const char *)buf + total, len - total);
        if (n <= 0) return -1;
        total += n;
    }
    return (ssize_t)total;
}

/* ========================================================================
 * TCP handshake: exchange fi_getname addresses with server
 * ======================================================================== */

static fi_addr_t tcpHandshake(FabricContext *ctx, int tcp_fd) {
    uint8_t local_name[RDMA_MAX_EP_NAME];
    size_t local_name_len = RDMA_MAX_EP_NAME;
    uint8_t peer_name[RDMA_MAX_EP_NAME];
    uint32_t peer_name_len;
    fi_addr_t addr = FI_ADDR_UNSPEC;
    ssize_t n;
    int ret;

    /* Get our local EP name */
    ret = fi_getname(&ctx->ep->fid, local_name, &local_name_len);
    if (ret) {
        fprintf(stderr, "fi_getname failed: %s\n", fi_strerror(-ret));
        return FI_ADDR_UNSPEC;
    }

    /* Send our name (client sends first) */
    uint32_t len_net = htonl((uint32_t)local_name_len);
    n = tcpWriteFull(tcp_fd, &len_net, sizeof(len_net));
    if (n < 0) return FI_ADDR_UNSPEC;
    n = tcpWriteFull(tcp_fd, local_name, local_name_len);
    if (n < 0) return FI_ADDR_UNSPEC;

    /* Read server name */
    n = tcpReadFull(tcp_fd, &peer_name_len, sizeof(peer_name_len));
    if (n < 0) return FI_ADDR_UNSPEC;
    peer_name_len = ntohl(peer_name_len);
    if (peer_name_len > RDMA_MAX_EP_NAME) return FI_ADDR_UNSPEC;

    n = tcpReadFull(tcp_fd, peer_name, peer_name_len);
    if (n < 0) return FI_ADDR_UNSPEC;

    /* Insert into AV */
    ret = fi_av_insert(ctx->av, peer_name, 1, &addr, 0, NULL);
    if (ret != 1) {
        fprintf(stderr, "fi_av_insert failed: %s\n", fi_strerror(-ret));
        return FI_ADDR_UNSPEC;
    }

    return addr;
}

/* ========================================================================
 * Buffer setup / teardown
 * ======================================================================== */

static void rdmaDestroyIoBuf(FabricContext *ctx) {
    if (ctx->recv_mr) { fi_close(&ctx->recv_mr->fid); ctx->recv_mr = NULL; }
    free(ctx->recv_buf); ctx->recv_buf = NULL;

    if (ctx->send_mr) { fi_close(&ctx->send_mr->fid); ctx->send_mr = NULL; }
    free(ctx->send_buf); ctx->send_buf = NULL;

    if (ctx->cmd_mr) { fi_close(&ctx->cmd_mr->fid); ctx->cmd_mr = NULL; }
    free(ctx->cmd_buf); ctx->cmd_buf = NULL;
    free(ctx->cmd_ctx); ctx->cmd_ctx = NULL;
}

static int rdmaPostRecv(FabricContext *ctx, valkeyRdmaCmd *cmd) {
    int idx = (int)(cmd - ctx->cmd_buf);
    RdmaOpCtx *opctx = &ctx->cmd_ctx[idx];
    opctx->user_data = cmd;
    struct iovec iov = {.iov_base = cmd, .iov_len = sizeof(valkeyRdmaCmd)};
    struct fi_msg msg = {
        .msg_iov = &iov, .desc = &ctx->cmd_mr_desc,
        .iov_count = 1, .addr = FI_ADDR_UNSPEC, .context = opctx,
    };
    int ret = fi_recvmsg(ctx->ep, &msg, 0);
    if (ret) {
        fprintf(stderr, "fi_recvmsg failed: %s\n", fi_strerror(-ret));
        return -1;
    }
    return 0;
}

static int rdmaSetupIoBuf(FabricContext *ctx) {
    uint64_t access;
    int ret, i;

    /* CMD buffers: [0..RECV_POOL-1] for recv, [RECV_POOL..RECV_POOL+WQE-1] for send */
    size_t cmd_count = RDMA_RECV_POOL_SIZE + VALKEY_RDMA_MAX_WQE;
    size_t cmd_bytes = sizeof(valkeyRdmaCmd) * cmd_count;
    ctx->cmd_buf = calloc(cmd_bytes, 1);
    if (!ctx->cmd_buf) return -1;
    ctx->cmd_ctx = calloc(cmd_count, sizeof(RdmaOpCtx));
    if (!ctx->cmd_ctx) { free(ctx->cmd_buf); ctx->cmd_buf = NULL; return -1; }

    access = FI_SEND | FI_RECV;
    ret = fi_mr_reg(ctx->domain, ctx->cmd_buf, cmd_bytes, access, 0, 0, 0, &ctx->cmd_mr, NULL);
    if (ret) {
        fprintf(stderr, "fi_mr_reg cmd failed: %s\n", fi_strerror(-ret));
        goto destroy;
    }
    if (ctx->fi->domain_attr->mr_mode & FI_MR_ENDPOINT) {
        fi_mr_bind(ctx->cmd_mr, &ctx->ep->fid, 0);
        fi_mr_enable(ctx->cmd_mr);
    }
    ctx->cmd_mr_desc = fi_mr_desc(ctx->cmd_mr);

    /* Post recv buffers */
    for (i = 0; i < RDMA_RECV_POOL_SIZE; i++) {
        if (rdmaPostRecv(ctx, &ctx->cmd_buf[i]) != 0) goto destroy;
    }

    /* Initialize send slots as free */
    for (i = RDMA_RECV_POOL_SIZE; i < (int)cmd_count; i++) {
        ctx->cmd_buf[i].keepalive.opcode = VALKEY_RDMA_INVALID_OPCODE;
    }

    /* RX data buffer (remote writes here via RDMA) */
    access = FI_RECV | FI_SEND | FI_READ | FI_WRITE | FI_REMOTE_READ | FI_REMOTE_WRITE;
    ctx->recv_length = VALKEY_RDMA_DEFAULT_RX_LEN;
    ctx->recv_buf = calloc(ctx->recv_length, 1);
    ret = fi_mr_reg(ctx->domain, ctx->recv_buf, ctx->recv_length, access, 0, 0, 0,
                    &ctx->recv_mr, NULL);
    if (ret) {
        fprintf(stderr, "fi_mr_reg recv failed: %s\n", fi_strerror(-ret));
        goto destroy;
    }
    if (ctx->fi->domain_attr->mr_mode & FI_MR_ENDPOINT) {
        fi_mr_bind(ctx->recv_mr, &ctx->ep->fid, 0);
        fi_mr_enable(ctx->recv_mr);
    }
    ctx->recv_mr_desc = fi_mr_desc(ctx->recv_mr);

    return 0;

destroy:
    rdmaDestroyIoBuf(ctx);
    return -1;
}

static int rdmaAdjustSendbuf(FabricContext *ctx, unsigned int length) {
    uint64_t access = FI_SEND | FI_RECV | FI_READ | FI_WRITE | FI_REMOTE_READ | FI_REMOTE_WRITE;
    int ret;

    if (length == ctx->send_length) return 0;

    if (ctx->send_length) {
        fi_close(&ctx->send_mr->fid);
        free(ctx->send_buf);
        ctx->send_length = 0;
    }

    ctx->send_buf = calloc(length, 1);
    ctx->send_length = length;
    ret = fi_mr_reg(ctx->domain, ctx->send_buf, length, access, 0, 0, 0, &ctx->send_mr, NULL);
    if (ret) {
        fprintf(stderr, "fi_mr_reg send failed: %s\n", fi_strerror(-ret));
        free(ctx->send_buf);
        ctx->send_buf = NULL;
        ctx->send_length = 0;
        return -1;
    }
    if (ctx->fi->domain_attr->mr_mode & FI_MR_ENDPOINT) {
        fi_mr_bind(ctx->send_mr, &ctx->ep->fid, 0);
        fi_mr_enable(ctx->send_mr);
    }
    ctx->send_mr_desc = fi_mr_desc(ctx->send_mr);

    return 0;
}

/* ========================================================================
 * Command send/recv handling
 * ======================================================================== */

static int rdmaSendCommand(FabricContext *ctx, valkeyRdmaCmd *cmd) {
    valkeyRdmaCmd *_cmd;
    int i, ret;

    for (i = RDMA_RECV_POOL_SIZE; i < RDMA_RECV_POOL_SIZE + VALKEY_RDMA_MAX_WQE; i++) {
        _cmd = &ctx->cmd_buf[i];
        if (_cmd->keepalive.opcode == VALKEY_RDMA_INVALID_OPCODE) break;
    }
    if (i == RDMA_RECV_POOL_SIZE + VALKEY_RDMA_MAX_WQE) {
        rdmaFatal("no free send cmd slot");
        return -1;
    }

    memcpy(_cmd, cmd, sizeof(valkeyRdmaCmd));

    RdmaOpCtx *opctx = &ctx->cmd_ctx[i];
    opctx->user_data = _cmd;
    struct iovec iov = {.iov_base = _cmd, .iov_len = sizeof(valkeyRdmaCmd)};
    struct fi_msg msg = {
        .msg_iov = &iov, .desc = &ctx->cmd_mr_desc,
        .iov_count = 1, .addr = ctx->peer_addr, .context = opctx,
    };

    ret = fi_sendmsg(ctx->ep, &msg, FI_COMPLETION);
    if (ret) {
        fprintf(stderr, "fi_sendmsg failed: %s\n", fi_strerror(-ret));
        _cmd->keepalive.opcode = VALKEY_RDMA_INVALID_OPCODE;
        return -1;
    }

    return 0;
}

static int connRdmaRegisterRx(FabricContext *ctx) {
    valkeyRdmaCmd cmd = {0};

    cmd.memory.opcode = htons(RegisterXferMemory);
    cmd.memory.addr = htobe64((uint64_t)(uintptr_t)ctx->recv_buf);
    cmd.memory.length = htonl(ctx->recv_length);
    cmd.memory.key = htobe64(fi_mr_key(ctx->recv_mr));

    ctx->rx_offset = 0;
    ctx->recv_offset = 0;

    return rdmaSendCommand(ctx, &cmd);
}

static int connRdmaHandleRecv(FabricContext *ctx, valkeyRdmaCmd *cmd, uint32_t byte_len) {
    if (byte_len != sizeof(valkeyRdmaCmd)) {
        rdmaFatal("recv corrupted cmd");
        return -1;
    }

    switch (ntohs(cmd->keepalive.opcode)) {
    case RegisterXferMemory:
        ctx->tx_addr = (char *)(uintptr_t)be64toh(cmd->memory.addr);
        ctx->tx_length = ntohl(cmd->memory.length);
        ctx->tx_key = be64toh(cmd->memory.key);
        ctx->tx_offset = 0;
        rdmaAdjustSendbuf(ctx, ctx->tx_length);
        break;
    case Keepalive: break;
    default:
        rdmaFatal("unknown cmd opcode");
        return -1;
    }

    return rdmaPostRecv(ctx, cmd);
}

static int connRdmaHandleRecvImm(FabricContext *ctx, valkeyRdmaCmd *cmd, uint32_t byte_len) {
    assert(byte_len + ctx->rx_offset <= ctx->recv_length);
    ctx->rx_offset += byte_len;
    return rdmaPostRecv(ctx, cmd);
}

static int connRdmaHandleSend(valkeyRdmaCmd *cmd) {
    memset(cmd, 0, sizeof(*cmd));
    cmd->keepalive.opcode = VALKEY_RDMA_INVALID_OPCODE;
    return 0;
}

/* ========================================================================
 * CQ handler (polls shared CQ with fi_cq_readfrom)
 * ======================================================================== */

static int connRdmaHandleCq(FabricContext *ctx) {
    struct fi_cq_data_entry cqe;
    fi_addr_t src_addr;
    int ret;

    for (;;) {
        ret = fi_cq_readfrom(ctx->cq, &cqe, 1, &src_addr);
        if (ret == -FI_EAGAIN) return 0;
        if (ret == -FI_EAVAIL) {
            struct fi_cq_err_entry err = {0};
            fi_cq_readerr(ctx->cq, &err, 0);
            fprintf(stderr, "CQ error: %s\n", fi_strerror(err.err));
            return -1;
        }
        if (ret < 0) {
            fprintf(stderr, "fi_cq_readfrom: %s\n", fi_strerror(-ret));
            return -1;
        }

        if (cqe.flags & FI_RECV) {
            if (cqe.flags & FI_REMOTE_CQ_DATA) {
                /* RDMA write with immediate */
                uint32_t imm = (uint32_t)cqe.data;
                if (connRdmaHandleRecvImm(ctx, (valkeyRdmaCmd *)cqe.buf, imm) != 0)
                    return -1;
            } else {
                /* Control command */
                if (connRdmaHandleRecv(ctx, (valkeyRdmaCmd *)cqe.buf, cqe.len) != 0)
                    return -1;
            }
        } else if (cqe.flags & FI_SEND) {
            RdmaOpCtx *opctx = (RdmaOpCtx *)cqe.op_context;
            connRdmaHandleSend((valkeyRdmaCmd *)opctx->user_data);
        } else if (cqe.flags & FI_RMA) {
            /* RDMA write completion, nothing to do */
        }
    }
}

/* ========================================================================
 * RDMA read / write (data path)
 * ======================================================================== */

static ssize_t valkeyRdmaRead(FabricContext *ctx, char *buf, size_t data_len) {
    long timed = 3000;
    long start = valkeyNowMs();
    uint32_t toread, remained;

copy:
    if (ctx->recv_offset < ctx->rx_offset) {
        remained = ctx->rx_offset - ctx->recv_offset;
        toread = MIN(remained, data_len);
        memcpy(buf, ctx->recv_buf + ctx->recv_offset, toread);
        ctx->recv_offset += toread;

        if (ctx->recv_offset == ctx->recv_length) {
            connRdmaRegisterRx(ctx);
        }
        return toread;
    }

pollcq:
    if (connRdmaHandleCq(ctx) == -1) return -1;
    if (ctx->recv_offset < ctx->rx_offset) goto copy;

    usleep(100);  /* 100us busy-poll (EFA: no FI_WAIT_FD) */

    if ((valkeyNowMs() - start) < timed) goto pollcq;

    rdmaFatal("read timeout");
    return -1;
}

static ssize_t valkeyRdmaReadFull(FabricContext *ctx, char *buf, size_t data_len) {
    size_t inbytes = 0;
    do {
        ssize_t n = valkeyRdmaRead(ctx, buf + inbytes, data_len - inbytes);
        if (n < 0) return -1;
        inbytes += n;
    } while (inbytes < data_len);
    return data_len;
}

static size_t connRdmaSend(FabricContext *ctx, const void *data, size_t data_len) {
    uint32_t off = ctx->tx_offset;
    char *addr = ctx->send_buf + off;
    int ret;

    assert(data_len <= ctx->tx_length - ctx->tx_offset);
    memcpy(addr, data, data_len);

    struct iovec iov = {.iov_base = addr, .iov_len = data_len};
    struct fi_rma_iov rma_iov = {
        .addr = (uint64_t)(uintptr_t)(ctx->tx_addr + off),
        .len = data_len,
        .key = ctx->tx_key,
    };
    struct fi_msg_rma msg = {
        .msg_iov = &iov, .desc = &ctx->send_mr_desc,
        .iov_count = 1, .addr = ctx->peer_addr,
        .rma_iov = &rma_iov, .rma_iov_count = 1,
        .context = &ctx->rma_ctx,
        .data = (uint64_t)htonl((uint32_t)data_len),
    };

    uint64_t flags = FI_REMOTE_CQ_DATA;
    if (++ctx->send_ops % (VALKEY_RDMA_MAX_WQE / 2) == 0) {
        flags |= FI_COMPLETION;
    }

    ret = fi_writemsg(ctx->ep, &msg, flags);
    if (ret) {
        fprintf(stderr, "fi_writemsg failed: %s\n", fi_strerror(-ret));
        return (size_t)-1;
    }

    ctx->tx_offset += data_len;
    return data_len;
}

static ssize_t valkeyRdmaWrite(FabricContext *ctx, char *buf, size_t data_len) {
    long timed = 3000;
    long start = valkeyNowMs();
    uint32_t towrite, wrote = 0;
    size_t ret;

    goto pollcq;

waitcq:
    usleep(100);  /* 100us busy-poll (EFA: no FI_WAIT_FD) */

pollcq:
    if (connRdmaHandleCq(ctx) == -1) return -1;

    assert(ctx->tx_offset <= ctx->tx_length);
    if (ctx->tx_offset == ctx->tx_length) goto waitcq;

    towrite = MIN(ctx->tx_length - ctx->tx_offset, data_len - wrote);
    ret = connRdmaSend(ctx, buf + wrote, towrite);
    if (ret == (size_t)-1) return -1;

    wrote += ret;
    if (wrote == data_len) return data_len;

    if ((valkeyNowMs() - start) < timed) goto waitcq;

    rdmaFatal("write timeout");
    return -1;
}

/* ========================================================================
 * Close / cleanup
 * ======================================================================== */

static void valkeyRdmaClose(FabricContext *ctx) {
    if (ctx->cq) connRdmaHandleCq(ctx);

    if (ctx->peer_addr != FI_ADDR_UNSPEC)
        fi_av_remove(ctx->av, &ctx->peer_addr, 1, 0);

    rdmaDestroyIoBuf(ctx);

    if (ctx->ep) fi_close(&ctx->ep->fid);
    if (ctx->av) fi_close(&ctx->av->fid);
    if (ctx->cq) fi_close(&ctx->cq->fid);
    if (ctx->domain) fi_close(&ctx->domain->fid);
    if (ctx->fabric) fi_close(&ctx->fabric->fid);
    if (ctx->fi) fi_freeinfo(ctx->fi);
}

/* ========================================================================
 * Connect: create fabric resources, TCP handshake, register RX
 * ======================================================================== */

static FabricContext *valkeyContextConnectFabric(const char *addr, int port, int timeout) {
    FabricContext *ctx = NULL;
    struct fi_info *hints, *fi;
    struct fi_cq_attr cq_attr = {0};
    struct fi_av_attr av_attr = {0};
    struct addrinfo ai_hints, *servinfo = NULL, *p;
    char _port[6];
    int tcp_fd = -1, ret;
    long start = valkeyNowMs();

    UNUSED(timeout);

    ctx = calloc(1, sizeof(FabricContext));
    if (!ctx) return NULL;
    ctx->peer_addr = FI_ADDR_UNSPEC;

    /* Get fabric info */
    hints = fi_allocinfo();
    if (!hints) goto err;
    hints->caps = FI_MSG | FI_RMA | FI_SOURCE;
    hints->ep_attr->type = FI_EP_RDM;
    hints->mode = FI_CONTEXT2 | FI_RX_CQ_DATA;
    hints->domain_attr->mr_mode = FI_MR_LOCAL | FI_MR_VIRT_ADDR | FI_MR_ALLOCATED | FI_MR_PROV_KEY | FI_MR_ENDPOINT;
    hints->tx_attr->msg_order = FI_ORDER_SAS;
    hints->rx_attr->msg_order = FI_ORDER_SAS;

    ret = fi_getinfo(FI_VERSION(1, 6), NULL, NULL, 0, hints, &fi);
    fi_freeinfo(hints);
    if (ret) {
        fprintf(stderr, "fi_getinfo: %s\n", fi_strerror(-ret));
        goto err;
    }
    ctx->fi = fi;

    /* Create fabric, domain */
    ret = fi_fabric(fi->fabric_attr, &ctx->fabric, NULL);
    if (ret) goto err;
    ret = fi_domain(ctx->fabric, fi, &ctx->domain, NULL);
    if (ret) goto err;

    /* CQ */
    cq_attr.size = fi->tx_attr->size + fi->rx_attr->size;
    if (cq_attr.size < (size_t)(VALKEY_RDMA_MAX_WQE * 4))
        cq_attr.size = VALKEY_RDMA_MAX_WQE * 4;
    cq_attr.format = FI_CQ_FORMAT_DATA;
    cq_attr.wait_obj = FI_WAIT_NONE;
    ret = fi_cq_open(ctx->domain, &cq_attr, &ctx->cq, NULL);
    if (ret) goto err;

    /* AV */
    av_attr.type = FI_AV_TABLE;
    av_attr.count = 16;
    ret = fi_av_open(ctx->domain, &av_attr, &ctx->av, NULL);
    if (ret) goto err;

    /* Endpoint */
    ret = fi_endpoint(ctx->domain, fi, &ctx->ep, NULL);
    if (ret) goto err;
    fi_ep_bind(ctx->ep, &ctx->cq->fid, FI_TRANSMIT | FI_RECV);
    fi_ep_bind(ctx->ep, &ctx->av->fid, 0);
    ret = fi_enable(ctx->ep);
    if (ret) goto err;

    /* Setup I/O buffers */
    if (rdmaSetupIoBuf(ctx) != 0) goto err;

    /* TCP connect for handshake */
    snprintf(_port, sizeof(_port), "%d", port);
    memset(&ai_hints, 0, sizeof(ai_hints));
    ai_hints.ai_family = AF_UNSPEC;
    ai_hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(addr, _port, &ai_hints, &servinfo)) {
        fprintf(stderr, "getaddrinfo failed\n");
        goto err;
    }

    for (p = servinfo; p; p = p->ai_next) {
        tcp_fd = socket(p->ai_family, SOCK_STREAM, p->ai_protocol);
        if (tcp_fd == -1) continue;
        if (connect(tcp_fd, p->ai_addr, p->ai_addrlen) == 0) break;
        close(tcp_fd);
        tcp_fd = -1;
    }
    freeaddrinfo(servinfo);

    if (tcp_fd < 0) {
        fprintf(stderr, "TCP connect to %s:%d failed\n", addr, port);
        goto err;
    }

    /* Exchange EP names */
    ctx->peer_addr = tcpHandshake(ctx, tcp_fd);
    close(tcp_fd);

    if (ctx->peer_addr == FI_ADDR_UNSPEC) {
        fprintf(stderr, "TCP handshake failed\n");
        goto err;
    }

    /* Register RX buffer with server */
    if (connRdmaRegisterRx(ctx) != 0) goto err;

    /* Wait for server to send us its RX registration */
    while (!ctx->send_buf && (valkeyNowMs() - start) < 3000) {
        connRdmaHandleCq(ctx);
        if (!ctx->send_buf) usleep(100);  /* 100us busy-poll */
    }

    if (!ctx->send_buf) {
        fprintf(stderr, "Timeout waiting for server RX registration\n");
        goto err;
    }

    ctx->connected = true;
    printf("Connected to %s:%d via libfabric RDM (provider: %s)\n",
           addr, port, fi->fabric_attr->prov_name);
    return ctx;

err:
    if (ctx) {
        valkeyRdmaClose(ctx);
        free(ctx);
    }
    return NULL;
}

/* ========================================================================
 * Test routine (same logic as rdma-test.c)
 * ======================================================================== */

static int port = 6379;
static char *host = NULL;
static int minkeys = 128;
static int maxkeys = 8192;
static int keysize = 1024 + 1;

struct test_kv_pair {
    char key[32];
    char *value;
};

static void *test_routine(void *arg) {
    pid_t tid = gettid();
    FabricContext *ctx;
    struct test_kv_pair *kv_pairs = NULL, *kv_pair;
    int keys;

    UNUSED(arg);

    ctx = valkeyContextConnectFabric(host, port, 3000);
    if (!ctx) rdmaFatal("fabric connect failed");

    int bufsize = keysize + 128;
    char *inbuf = malloc(bufsize);
    char *outbuf = malloc(bufsize);
    int inbytes, outbytes;

    /* Round 1: PING */
    char *pingcmd = "*1\r\n$4\r\nPING\r\n";
    char *pingresp = "+PONG\r\n";

    valkeyRdmaWrite(ctx, pingcmd, strlen(pingcmd));
    inbytes = valkeyRdmaReadFull(ctx, inbuf, strlen(pingresp));
    assert(!strncmp(pingresp, inbuf, inbytes));
    printf("Fabric RDMA test thread[%d] PING/PONG [OK]\n", tid);

    /* Prepare random KVs */
    keys = random() % (maxkeys - minkeys) + minkeys;
    kv_pairs = calloc(sizeof(struct test_kv_pair), keys);
    for (int i = 0; i < keys; i++) {
        kv_pair = &kv_pairs[i];
        snprintf(kv_pair->key, sizeof(kv_pair->key) - 1, "THREAD%02d-%06d", tid, i);
        kv_pair->value = calloc(keysize, 1);
        for (int k = 0; k < keysize - 1; k++)
            kv_pair->value[k] = 'A' + random() % 26;
    }
    printf("Fabric RDMA test thread[%d] prepare %d KVs [OK]\n", tid, keys);

    /* Round 2: SET */
    char *okresp = "+OK\r\n";
    for (int i = 0; i < keys; i++) {
        kv_pair = &kv_pairs[i];
        outbytes = sprintf(outbuf, "*3\r\n$3\r\nSET\r\n$%ld\r\n%s\r\n$%ld\r\n%s\r\n",
                           strlen(kv_pair->key), kv_pair->key,
                           strlen(kv_pair->value), kv_pair->value);
        valkeyRdmaWrite(ctx, outbuf, outbytes);
        inbytes = valkeyRdmaReadFull(ctx, inbuf, strlen(okresp));
        assert(!strncmp("+OK\r\n", inbuf, inbytes));
    }
    printf("Fabric RDMA test thread[%d] SET %d KVs [OK]\n", tid, keys);

    /* Round 3: BGSAVE (once) */
    char *bgsavecmd = "*1\r\n$6\r\nBGSAVE\r\n";
    char *bgsaveresp = "+Background saving started\r\n";
    static int bgsaved;
    if (!__atomic_fetch_add(&bgsaved, 1, __ATOMIC_SEQ_CST)) {
        valkeyRdmaWrite(ctx, bgsavecmd, strlen(bgsavecmd));
        inbytes = valkeyRdmaReadFull(ctx, inbuf, strlen(bgsaveresp));
        assert(!strncmp(bgsaveresp, inbuf, inbytes));
        printf("Fabric RDMA test thread[%d] BGSAVE [OK]\n", tid);
    }

    /* Round 4: GET + verify */
    char *getrespprex = "$1024\r\n";
    int getrespprexlen = strlen(getrespprex);
    for (int i = 0; i < keys; i++) {
        kv_pair = &kv_pairs[i];
        outbytes = sprintf(outbuf, "*2\r\n$3\r\nGET\r\n$%ld\r\n%s\r\n",
                           strlen(kv_pair->key), kv_pair->key);
        valkeyRdmaWrite(ctx, outbuf, outbytes);
        inbytes = valkeyRdmaReadFull(ctx, inbuf, getrespprexlen + strlen(kv_pair->value) + 2);
        assert(!strncmp(getrespprex, inbuf, getrespprexlen));
        assert(!strncmp(kv_pair->value, inbuf + getrespprexlen, strlen(kv_pair->value)));
    }
    printf("Fabric RDMA test thread[%d] GET %d KVs [OK]\n", tid, keys);

    /* Cleanup */
    for (int i = 0; i < keys; i++) free(kv_pairs[i].value);
    free(kv_pairs);
    free(inbuf);
    free(outbuf);
    valkeyRdmaClose(ctx);
    free(ctx);

    return NULL;
}

/* ========================================================================
 * Main
 * ======================================================================== */

void usage(char *proc) {
    printf("%s usage:\n", proc);
    printf("\t--help/-H\n");
    printf("\t--host/-h HOSTADDR\n");
    printf("\t--port/-p PORT\n");
    printf("\t--maxkeys/-M MAXKEYS\n");
    printf("\t--minkeys/-m MINKEYS\n");
    printf("\t--thread/-t THREADS\n");
}

int main(int argc, char *argv[]) {
    int c, args;
    int nr_threads = 0;
    pthread_t threads[MAX_THREADS];

    static struct option long_opts[] = {
        {"help", no_argument, NULL, 'H'},
        {"host", required_argument, NULL, 'h'},
        {"port", required_argument, NULL, 'p'},
        {"maxkeys", required_argument, NULL, 'M'},
        {"minkeys", required_argument, NULL, 'm'},
        {"thread", required_argument, NULL, 't'},
        {0, 0, 0, 0},
    };

    while ((c = getopt_long(argc, argv, "Hh:p:t:M:m:", long_opts, &args)) != -1) {
        switch (c) {
        case 'h': host = optarg; break;
        case 'p':
            port = atoi(optarg);
            if (port <= 0 || port > 65535) rdmaFatal("invalid port");
            break;
        case 't':
            nr_threads = atoi(optarg);
            if (nr_threads < 0 || nr_threads > MAX_THREADS)
                rdmaFatal("threads must be [0, 32]");
            break;
        case 'M': maxkeys = atoi(optarg); break;
        case 'm': minkeys = atoi(optarg); break;
        case 'H': usage(argv[0]); exit(0);
        default: usage(argv[0]); exit(-1);
        }
    }

    if (!host) rdmaFatal("missing --host/-h");
    if (minkeys > maxkeys) rdmaFatal("minkeys > maxkeys");

    srandom(time(NULL) ^ getpid());

    if (!nr_threads) {
        printf("Test a single client in main thread ...\n");
        test_routine(NULL);
        return 0;
    }

    for (int i = 0; i < nr_threads; i++)
        assert(!pthread_create(&threads[i], NULL, test_routine, NULL));
    for (int i = 0; i < nr_threads; i++)
        pthread_join(threads[i], NULL);

    printf("Valkey Over RDMA (libfabric) test [OK]\n");
    return 0;
}

#endif /* __linux__ */
