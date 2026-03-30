/* ==========================================================================
 * rdma_transport_fabric.h - libfabric/OFI backend for RDMA transport.
 * --------------------------------------------------------------------------
 * Implements rdmaTransportOps using libfabric (Open Fabrics Interfaces).
 * Uses the verbs provider by default for wire-protocol compatibility with
 * existing ibverbs-based clients, but supports any provider with
 * FI_EP_MSG + FI_RMA + FI_REMOTE_CQ_DATA capabilities.
 *
 * Copyright (c) Valkey Contributors
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * ==========================================================================
 */

#ifndef RDMA_TRANSPORT_FABRIC_H
#define RDMA_TRANSPORT_FABRIC_H

#include "rdma_transport.h"

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_eq.h>
#include <rdma/fi_errno.h>

/* -------------------------------------------------------------------------
 * Concrete type definitions for libfabric backend
 * ------------------------------------------------------------------------- */

struct rdmaTransportDomain {
    struct fid_domain *domain;
    struct fid_fabric *fabric;    /* back-reference for cleanup */
};

struct rdmaTransportCQ {
    struct fid_cq *cq;
    int wait_fd;
};

struct rdmaTransportMR {
    struct fid_mr *mr;
    uint64_t key;
};

struct rdmaTransportEP {
    struct fid_ep *ep;
    struct fi_info *fi;
    struct fid_fabric *fabric;
    struct fid_domain *domain;
    struct fid_eq *eq;               /* per-EP event queue for CM events */
    void *user_context;
    struct sockaddr_storage local_addr;
    struct sockaddr_storage peer_addr;
    int has_local_addr;
    int has_peer_addr;
};

struct rdmaTransportEQ {
    struct fid_eq *eq;
    struct fi_info *fi_hints;        /* saved hints for fi_getinfo */
    struct fid_fabric *fabric;
    int wait_fd;
};

struct rdmaTransportPEP {
    struct fid_pep *pep;
    struct fid_fabric *fabric;
    struct fid_eq *eq;               /* shared reference */
    struct fi_info *fi;
    int wait_fd;
};

/* -------------------------------------------------------------------------
 * Helper: map abstract access flags to libfabric MR access flags
 * ------------------------------------------------------------------------- */
static inline uint64_t fabricAccessFlags(int flags) {
    uint64_t fi_flags = 0;
    if (flags & RDMA_TRANSPORT_ACCESS_LOCAL_WRITE)
        fi_flags |= FI_READ | FI_WRITE;
    if (flags & RDMA_TRANSPORT_ACCESS_REMOTE_READ)
        fi_flags |= FI_REMOTE_READ;
    if (flags & RDMA_TRANSPORT_ACCESS_REMOTE_WRITE)
        fi_flags |= FI_REMOTE_WRITE;
    return fi_flags;
}

/* -------------------------------------------------------------------------
 * Implementation
 * ------------------------------------------------------------------------- */

static int fabricInit(void) {
    /* libfabric handles fork safety internally via providers */
    return 0;
}

static void fabricCleanup(void) {
    /* no-op */
}

static rdmaTransportDomain *fabricAllocDomain(rdmaTransportEP *ep) {
    rdmaTransportDomain *tdomain = zmalloc(sizeof(*tdomain));
    tdomain->domain = ep->domain;
    tdomain->fabric = ep->fabric;
    /* domain is managed by the EP lifecycle, don't close it in free_domain */
    return tdomain;
}

static void fabricFreeDomain(rdmaTransportDomain *domain) {
    if (!domain) return;
    /* domain/fabric are owned by the EP, just free the wrapper */
    zfree(domain);
}

static rdmaTransportCQ *fabricCreateCQ(rdmaTransportEP *ep, int cq_size,
                                        rdmaTransportDomain *domain, int comp_vector) {
    UNUSED(comp_vector);
    struct fi_cq_attr cq_attr = {0};
    rdmaTransportCQ *tcq = zmalloc(sizeof(*tcq));

    cq_attr.size = cq_size;
    cq_attr.format = FI_CQ_FORMAT_DATA;
    cq_attr.wait_obj = FI_WAIT_FD;

    if (fi_cq_open(domain->domain, &cq_attr, &tcq->cq, NULL)) {
        zfree(tcq);
        return NULL;
    }

    /* Get the wait fd for event loop integration */
    if (fi_control(&tcq->cq->fid, FI_GETWAIT, &tcq->wait_fd)) {
        fi_close(&tcq->cq->fid);
        zfree(tcq);
        return NULL;
    }

    return tcq;
}

static void fabricDestroyCQ(rdmaTransportCQ *tcq) {
    if (!tcq) return;
    if (tcq->cq) fi_close(&tcq->cq->fid);
    zfree(tcq);
}

static int fabricGetCQFd(rdmaTransportCQ *tcq) {
    return tcq->wait_fd;
}

static int fabricNotifyCQ(rdmaTransportCQ *tcq) {
    UNUSED(tcq);
    /* libfabric CQs with FI_WAIT_FD auto-notify */
    return 0;
}

static int fabricCreateEP(rdmaTransportEP *ep, rdmaTransportDomain *domain,
                           rdmaTransportEPAttr *attr) {
    UNUSED(domain);
    struct fi_info *fi = ep->fi;

    /* Set endpoint capabilities */
    fi->tx_attr->size = attr->max_send_wr;
    fi->rx_attr->size = attr->max_recv_wr;
    fi->tx_attr->iov_limit = attr->max_send_sge;
    fi->rx_attr->iov_limit = attr->max_recv_sge;

    if (fi_endpoint(ep->domain, fi, &ep->ep, NULL)) {
        return -1;
    }

    /* Bind EP to EQ for CM events */
    if (ep->eq && fi_ep_bind(ep->ep, &ep->eq->fid, 0)) {
        fi_close(&ep->ep->fid);
        ep->ep = NULL;
        return -1;
    }

    /* Bind CQ for send and recv completions */
    if (attr->send_cq && fi_ep_bind(ep->ep, &attr->send_cq->cq->fid, FI_TRANSMIT | FI_RECV)) {
        fi_close(&ep->ep->fid);
        ep->ep = NULL;
        return -1;
    }

    /* Enable the endpoint */
    if (fi_enable(ep->ep)) {
        fi_close(&ep->ep->fid);
        ep->ep = NULL;
        return -1;
    }

    return 0;
}

static void fabricDestroyEP(rdmaTransportEP *ep) {
    if (!ep) return;
    if (ep->ep) {
        fi_close(&ep->ep->fid);
        ep->ep = NULL;
    }
}

static int fabricQueryDeviceMaxSGE(rdmaTransportEP *ep) {
    if (ep->fi && ep->fi->tx_attr) {
        return (int)ep->fi->tx_attr->iov_limit;
    }
    return 1;
}

static rdmaTransportMR *fabricRegMR(rdmaTransportDomain *domain, void *buf,
                                     size_t len, int access_flags) {
    rdmaTransportMR *tmr = zmalloc(sizeof(*tmr));
    uint64_t fi_flags = fabricAccessFlags(access_flags);

    if (fi_mr_reg(domain->domain, buf, len, fi_flags, 0, 0, 0, &tmr->mr, NULL)) {
        zfree(tmr);
        return NULL;
    }

    tmr->key = fi_mr_key(tmr->mr);
    return tmr;
}

static void fabricDeregMR(rdmaTransportMR *tmr) {
    if (!tmr) return;
    if (tmr->mr) fi_close(&tmr->mr->fid);
    zfree(tmr);
}

static uint32_t fabricMRLkey(rdmaTransportMR *tmr) {
    /* libfabric uses fi_mr_desc() for local access */
    return (uint32_t)(uintptr_t)fi_mr_desc(tmr->mr);
}

static uint32_t fabricMRRkey(rdmaTransportMR *tmr) {
    return (uint32_t)tmr->key;
}

/* --- Data path --- */

static int fabricPostRecv(rdmaTransportEP *ep, void *buf, size_t len,
                           rdmaTransportMR *mr, uint64_t wr_id) {
    void *desc = fi_mr_desc(mr->mr);
    struct iovec iov = {.iov_base = buf, .iov_len = len};
    struct fi_msg msg = {0};

    msg.msg_iov = &iov;
    msg.desc = &desc;
    msg.iov_count = 1;
    msg.context = (void *)(uintptr_t)wr_id;

    return fi_recvmsg(ep->ep, &msg, 0) ? -1 : 0;
}

static int fabricPostSend(rdmaTransportEP *ep, void *buf, size_t len,
                           rdmaTransportMR *mr, uint64_t wr_id, int signaled) {
    void *desc = fi_mr_desc(mr->mr);
    struct iovec iov = {.iov_base = buf, .iov_len = len};
    struct fi_msg msg = {0};
    uint64_t flags = signaled ? FI_COMPLETION : 0;

    msg.msg_iov = &iov;
    msg.desc = &desc;
    msg.iov_count = 1;
    msg.context = (void *)(uintptr_t)wr_id;

    return fi_sendmsg(ep->ep, &msg, flags) ? -1 : 0;
}

static int fabricPostRdmaWriteImm(rdmaTransportEP *ep,
                                    void *local_buf, size_t len,
                                    rdmaTransportMR *local_mr,
                                    uint64_t remote_addr, uint32_t rkey,
                                    uint32_t imm_data, uint64_t wr_id,
                                    int signaled) {
    void *desc = fi_mr_desc(local_mr->mr);
    struct iovec iov = {.iov_base = local_buf, .iov_len = len};
    struct fi_rma_iov rma_iov = {
        .addr = remote_addr,
        .len = len,
        .key = rkey,
    };
    struct fi_msg_rma msg = {0};
    uint64_t flags = FI_REMOTE_CQ_DATA;
    if (signaled) flags |= FI_COMPLETION;

    msg.msg_iov = &iov;
    msg.desc = &desc;
    msg.iov_count = 1;
    msg.rma_iov = &rma_iov;
    msg.rma_iov_count = 1;
    msg.context = (void *)(uintptr_t)wr_id;
    msg.data = imm_data;

    return fi_writemsg(ep->ep, &msg, flags) ? -1 : 0;
}

/* --- Completion handling --- */

static int fabricGetCQEvent(rdmaTransportCQ *tcq) {
    UNUSED(tcq);
    /* With FI_WAIT_FD, the fd is already signaled when data is available.
     * No separate "get event + ack" cycle needed. Return success. */
    return 1;
}

static void fabricAckCQEvent(rdmaTransportCQ *tcq) {
    UNUSED(tcq);
    /* no-op for libfabric */
}

static int fabricPollCQ(rdmaTransportCQ *tcq, rdmaTransportWC *wc) {
    struct fi_cq_data_entry entry;
    struct fi_cq_err_entry err_entry;
    ssize_t ret;

    ret = fi_cq_read(tcq->cq, &entry, 1);
    if (ret == 0 || ret == -FI_EAGAIN) return 0;

    if (ret == -FI_EAVAIL) {
        fi_cq_readerr(tcq->cq, &err_entry, 0);
        wc->status = err_entry.err;
        wc->wr_id = (uint64_t)(uintptr_t)err_entry.op_context;
        wc->opcode = RDMA_TRANSPORT_WC_UNKNOWN;
        wc->byte_len = 0;
        wc->imm_data = 0;
        return 1;
    }

    if (ret < 0) return -1;

    /* Success */
    wc->status = 0;
    wc->wr_id = (uint64_t)(uintptr_t)entry.op_context;
    wc->byte_len = (uint32_t)entry.len;
    wc->imm_data = (uint32_t)entry.data;

    /* Map flags to opcode. In libfabric, we infer the operation type from flags. */
    if (entry.flags & FI_RECV) {
        if (entry.flags & FI_REMOTE_WRITE) {
            wc->opcode = RDMA_TRANSPORT_WC_RECV_RDMA_WITH_IMM;
        } else {
            wc->opcode = RDMA_TRANSPORT_WC_RECV;
        }
    } else if (entry.flags & FI_WRITE) {
        wc->opcode = RDMA_TRANSPORT_WC_RDMA_WRITE;
    } else if (entry.flags & FI_SEND) {
        wc->opcode = RDMA_TRANSPORT_WC_SEND;
    } else {
        wc->opcode = RDMA_TRANSPORT_WC_UNKNOWN;
    }

    return 1;
}

static const char *fabricWCStatusStr(int status) {
    return fi_strerror(status);
}

/* --- Connection Management (Server) --- */

static rdmaTransportEQ *fabricCreateEventChannel(void) {
    rdmaTransportEQ *teq = zmalloc(sizeof(*teq));
    memset(teq, 0, sizeof(*teq));

    /* Create hints for fi_getinfo */
    teq->fi_hints = fi_allocinfo();
    if (!teq->fi_hints) {
        zfree(teq);
        return NULL;
    }

    teq->fi_hints->ep_attr->type = FI_EP_MSG;
    teq->fi_hints->caps = FI_MSG | FI_RMA | FI_REMOTE_CQ_DATA;
    teq->fi_hints->mode = FI_LOCAL_MR;
    teq->fi_hints->domain_attr->mr_mode = FI_MR_LOCAL | FI_MR_ALLOCATED | FI_MR_PROV_KEY | FI_MR_VIRT_ADDR;

    return teq;
}

static void fabricDestroyEventChannel(rdmaTransportEQ *teq) {
    if (!teq) return;
    if (teq->eq) fi_close(&teq->eq->fid);
    if (teq->fabric) fi_close(&teq->fabric->fid);
    if (teq->fi_hints) fi_freeinfo(teq->fi_hints);
    zfree(teq);
}

static int fabricGetEQFd(rdmaTransportEQ *teq) {
    return teq->wait_fd;
}

static rdmaTransportPEP *fabricCreateListenEP(rdmaTransportEQ *eq, int af_only) {
    UNUSED(af_only);
    rdmaTransportPEP *pep = zmalloc(sizeof(*pep));
    memset(pep, 0, sizeof(*pep));
    pep->fabric = eq->fabric;
    pep->eq = eq->eq;
    pep->fi = NULL;

    if (fi_passive_ep(eq->fabric, eq->fi_hints, &pep->pep, NULL)) {
        zfree(pep);
        return NULL;
    }

    /* Bind PEP to EQ for connection events */
    if (fi_pep_bind(pep->pep, &eq->eq->fid, 0)) {
        fi_close(&pep->pep->fid);
        zfree(pep);
        return NULL;
    }

    return pep;
}

static void fabricDestroyListenEP(rdmaTransportPEP *pep) {
    if (!pep) return;
    if (pep->pep) fi_close(&pep->pep->fid);
    if (pep->fi) fi_freeinfo(pep->fi);
    zfree(pep);
}

static int fabricBindListen(rdmaTransportPEP *pep, struct sockaddr *addr, size_t addrlen) {
    UNUSED(addrlen);
    return fi_setname(&pep->pep->fid, addr, addrlen);
}

static int fabricListenEP(rdmaTransportPEP *pep, int backlog) {
    UNUSED(backlog);
    return fi_listen(pep->pep);
}

static int fabricGetCMEvent(rdmaTransportEQ *eq, rdmaTransportCMEventData *ev_data) {
    struct fi_eq_cm_entry cm_entry;
    struct fi_eq_err_entry err_entry;
    uint32_t event;
    ssize_t ret;

    ret = fi_eq_read(eq->eq, &event, &cm_entry, sizeof(cm_entry), 0);
    if (ret == -FI_EAGAIN) return 0;

    if (ret == -FI_EAVAIL) {
        fi_eq_readerr(eq->eq, &err_entry, 0);
        ev_data->event = RDMA_TRANSPORT_CM_ERROR;
        ev_data->new_ep = NULL;
        return 1;
    }

    if (ret < 0) return -1;

    ev_data->new_ep = NULL;
    switch (event) {
    case FI_CONNREQ: {
        ev_data->event = RDMA_TRANSPORT_CM_CONNECT_REQUEST;
        /* Create a new EP from the connection request info */
        rdmaTransportEP *new_ep = zmalloc(sizeof(*new_ep));
        memset(new_ep, 0, sizeof(*new_ep));
        new_ep->fi = cm_entry.info;
        new_ep->fabric = eq->fabric;
        ev_data->new_ep = new_ep;
        break;
    }
    case FI_CONNECTED:
        ev_data->event = RDMA_TRANSPORT_CM_ESTABLISHED;
        break;
    case FI_SHUTDOWN:
        ev_data->event = RDMA_TRANSPORT_CM_DISCONNECTED;
        break;
    default:
        ev_data->event = RDMA_TRANSPORT_CM_IGNORED;
        break;
    }

    return 1;
}

static int fabricAckCMEvent(rdmaTransportEQ *eq) {
    UNUSED(eq);
    /* libfabric EQ events don't need explicit acking */
    return 0;
}

static int fabricAccept(rdmaTransportEP *ep, rdmaTransportConnParam *param) {
    UNUSED(param);
    /* In libfabric, the endpoint must be created and bound before accept */
    return fi_accept(ep->ep, NULL, 0);
}

static int fabricReject(rdmaTransportEP *ep) {
    return fi_reject(ep->fabric, ep->fi->handle, NULL, 0);
}

/* --- Connection Management (Client) --- */

static rdmaTransportEP *fabricCreateClientEP(rdmaTransportEQ *eq) {
    rdmaTransportEP *ep = zmalloc(sizeof(*ep));
    memset(ep, 0, sizeof(*ep));
    ep->fabric = eq->fabric;
    ep->eq = eq->eq;
    ep->fi = NULL;
    return ep;
}

static int fabricResolveAddr(rdmaTransportEP *ep, struct sockaddr *addr, int timeout_ms) {
    struct fi_info *hints, *fi;
    UNUSED(timeout_ms);

    hints = fi_allocinfo();
    if (!hints) return -1;

    hints->ep_attr->type = FI_EP_MSG;
    hints->caps = FI_MSG | FI_RMA | FI_REMOTE_CQ_DATA;
    hints->mode = FI_LOCAL_MR;
    hints->domain_attr->mr_mode = FI_MR_LOCAL | FI_MR_ALLOCATED | FI_MR_PROV_KEY | FI_MR_VIRT_ADDR;
    hints->dest_addr = addr;
    hints->dest_addrlen = (addr->sa_family == AF_INET) ?
                          sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

    int ret = fi_getinfo(FI_VERSION(1, 6), NULL, NULL, 0, hints, &fi);
    hints->dest_addr = NULL; /* don't let fi_freeinfo free our addr */
    fi_freeinfo(hints);

    if (ret) return -1;

    ep->fi = fi;

    /* Create fabric and domain if not already set */
    if (!ep->fabric) {
        if (fi_fabric(fi->fabric_attr, &ep->fabric, NULL)) {
            fi_freeinfo(fi);
            ep->fi = NULL;
            return -1;
        }
    }

    if (!ep->domain) {
        if (fi_domain(ep->fabric, fi, &ep->domain, NULL)) {
            fi_freeinfo(fi);
            ep->fi = NULL;
            return -1;
        }
    }

    /* Store peer address */
    if (addr->sa_family == AF_INET) {
        memcpy(&ep->peer_addr, addr, sizeof(struct sockaddr_in));
    } else {
        memcpy(&ep->peer_addr, addr, sizeof(struct sockaddr_in6));
    }
    ep->has_peer_addr = 1;

    return 0;
}

static int fabricResolveRoute(rdmaTransportEP *ep, int timeout_ms) {
    UNUSED(ep);
    UNUSED(timeout_ms);
    /* In libfabric, route resolution is implicit in fi_getinfo/fi_connect */
    return 0;
}

static int fabricConnect(rdmaTransportEP *ep, rdmaTransportConnParam *param) {
    UNUSED(param);
    if (!ep->ep) return -1;
    return fi_connect(ep->ep, ep->fi->dest_addr, NULL, 0);
}

static int fabricDisconnect(rdmaTransportEP *ep) {
    if (ep->ep) {
        return fi_shutdown(ep->ep, 0);
    }
    return 0;
}

static int fabricGetLocalAddr(rdmaTransportEP *ep, struct sockaddr_storage *addr) {
    if (ep->has_local_addr) {
        memcpy(addr, &ep->local_addr, sizeof(*addr));
        return 0;
    }
    if (ep->ep) {
        size_t addrlen = sizeof(*addr);
        if (fi_getname(&ep->ep->fid, addr, &addrlen) == 0) {
            memcpy(&ep->local_addr, addr, sizeof(*addr));
            ep->has_local_addr = 1;
            return 0;
        }
    }
    return -1;
}

static int fabricGetPeerAddr(rdmaTransportEP *ep, struct sockaddr_storage *addr) {
    if (ep->has_peer_addr) {
        memcpy(addr, &ep->peer_addr, sizeof(*addr));
        return 0;
    }
    if (ep->ep) {
        size_t addrlen = sizeof(*addr);
        if (fi_getpeer(ep->ep, addr, &addrlen) == 0) {
            memcpy(&ep->peer_addr, addr, sizeof(*addr));
            ep->has_peer_addr = 1;
            return 0;
        }
    }
    return -1;
}

static int fabricGetPeerAddrFromRequest(rdmaTransportCMEventData *ev,
                                         struct sockaddr_storage *addr) {
    /* For CONNECT_REQUEST, the new_ep has fi_info with dest_addr from the peer */
    if (ev->new_ep && ev->new_ep->fi && ev->new_ep->fi->dest_addr) {
        memcpy(addr, ev->new_ep->fi->dest_addr, ev->new_ep->fi->dest_addrlen);
        return 0;
    }
    memcpy(addr, &ev->peer_addr, sizeof(*addr));
    return 0;
}

static void fabricSetEPContext(rdmaTransportEP *ep, void *ctx) {
    ep->user_context = ctx;
}

static void *fabricGetEPContext(rdmaTransportEP *ep) {
    return ep->user_context;
}

/* -------------------------------------------------------------------------
 * Operations table
 * ------------------------------------------------------------------------- */
const rdmaTransportOps rdmaTransportFabricOps = {
    .name = "fabric",

    .init = fabricInit,
    .cleanup = fabricCleanup,

    .alloc_domain = fabricAllocDomain,
    .free_domain = fabricFreeDomain,

    .create_cq = fabricCreateCQ,
    .destroy_cq = fabricDestroyCQ,
    .get_cq_fd = fabricGetCQFd,
    .notify_cq = fabricNotifyCQ,

    .create_ep = fabricCreateEP,
    .destroy_ep = fabricDestroyEP,
    .query_device_max_sge = fabricQueryDeviceMaxSGE,

    .reg_mr = fabricRegMR,
    .dereg_mr = fabricDeregMR,
    .mr_lkey = fabricMRLkey,
    .mr_rkey = fabricMRRkey,

    .post_recv = fabricPostRecv,
    .post_send = fabricPostSend,
    .post_rdma_write_imm = fabricPostRdmaWriteImm,

    .get_cq_event = fabricGetCQEvent,
    .ack_cq_event = fabricAckCQEvent,
    .poll_cq = fabricPollCQ,
    .wc_status_str = fabricWCStatusStr,

    .create_event_channel = fabricCreateEventChannel,
    .destroy_event_channel = fabricDestroyEventChannel,
    .get_eq_fd = fabricGetEQFd,

    .create_listen_ep = fabricCreateListenEP,
    .destroy_listen_ep = fabricDestroyListenEP,
    .bind_listen = fabricBindListen,
    .listen_ep = fabricListenEP,

    .get_cm_event = fabricGetCMEvent,
    .ack_cm_event = fabricAckCMEvent,

    .accept = fabricAccept,
    .reject = fabricReject,

    .create_client_ep = fabricCreateClientEP,
    .resolve_addr = fabricResolveAddr,
    .resolve_route = fabricResolveRoute,
    .connect = fabricConnect,

    .disconnect = fabricDisconnect,
    .get_local_addr = fabricGetLocalAddr,
    .get_peer_addr = fabricGetPeerAddr,
    .get_peer_addr_from_request = fabricGetPeerAddrFromRequest,

    .set_ep_context = fabricSetEPContext,
    .get_ep_context = fabricGetEPContext,
};

#endif /* RDMA_TRANSPORT_FABRIC_H */
