/* ==========================================================================
 * rdma_transport_verbs.h - ibverbs/rdma_cm backend for RDMA transport.
 * --------------------------------------------------------------------------
 * Implements rdmaTransportOps using libibverbs and librdmacm.
 * This is the traditional backend, preserving full backward compatibility.
 *
 * Copyright (c) Valkey Contributors
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * ==========================================================================
 */

#ifndef RDMA_TRANSPORT_VERBS_H
#define RDMA_TRANSPORT_VERBS_H

#include "rdma_transport.h"
#include <rdma/rdma_cma.h>

/* -------------------------------------------------------------------------
 * Concrete type definitions for ibverbs backend
 * ------------------------------------------------------------------------- */

struct rdmaTransportDomain {
    struct ibv_pd *pd;
};

struct rdmaTransportCQ {
    struct ibv_cq *cq;
    struct ibv_comp_channel *comp_channel;
};

struct rdmaTransportMR {
    struct ibv_mr *mr;
};

struct rdmaTransportEP {
    struct rdma_cm_id *cm_id;
};

struct rdmaTransportEQ {
    struct rdma_event_channel *cm_channel;
    struct rdma_cm_event *pending_event; /* event awaiting ack */
};

struct rdmaTransportPEP {
    struct rdma_cm_id *cm_id;
    struct rdma_event_channel *cm_channel; /* shared reference */
};

/* -------------------------------------------------------------------------
 * Helper: map abstract access flags to ibverbs access flags
 * ------------------------------------------------------------------------- */
static inline int verbsAccessFlags(int flags) {
    int ibv_flags = 0;
    if (flags & RDMA_TRANSPORT_ACCESS_LOCAL_WRITE) ibv_flags |= IBV_ACCESS_LOCAL_WRITE;
    if (flags & RDMA_TRANSPORT_ACCESS_REMOTE_READ) ibv_flags |= IBV_ACCESS_REMOTE_READ;
    if (flags & RDMA_TRANSPORT_ACCESS_REMOTE_WRITE) ibv_flags |= IBV_ACCESS_REMOTE_WRITE;
    return ibv_flags;
}

/* -------------------------------------------------------------------------
 * Implementation
 * ------------------------------------------------------------------------- */

static int verbsInit(void) {
    if (ibv_fork_init()) {
        return -1;
    }
    return 0;
}

static void verbsCleanup(void) {
    /* no-op for verbs */
}

static rdmaTransportDomain *verbsAllocDomain(rdmaTransportEP *ep) {
    rdmaTransportDomain *domain = zmalloc(sizeof(*domain));
    domain->pd = ibv_alloc_pd(ep->cm_id->verbs);
    if (!domain->pd) {
        zfree(domain);
        return NULL;
    }
    return domain;
}

static void verbsFreeDomain(rdmaTransportDomain *domain) {
    if (!domain) return;
    if (domain->pd) ibv_dealloc_pd(domain->pd);
    zfree(domain);
}

static rdmaTransportCQ *verbsCreateCQ(rdmaTransportEP *ep, int cq_size,
                                       rdmaTransportDomain *domain, int comp_vector) {
    UNUSED(domain);
    rdmaTransportCQ *tcq = zmalloc(sizeof(*tcq));

    tcq->comp_channel = ibv_create_comp_channel(ep->cm_id->verbs);
    if (!tcq->comp_channel) {
        zfree(tcq);
        return NULL;
    }

    /* clamp comp_vector */
    if (comp_vector < 0) comp_vector = abs((int)random());
    comp_vector = comp_vector % ep->cm_id->verbs->num_comp_vectors;

    tcq->cq = ibv_create_cq(ep->cm_id->verbs, cq_size, NULL, tcq->comp_channel, comp_vector);
    if (!tcq->cq) {
        ibv_destroy_comp_channel(tcq->comp_channel);
        zfree(tcq);
        return NULL;
    }

    ibv_req_notify_cq(tcq->cq, 0);
    return tcq;
}

static void verbsDestroyCQ(rdmaTransportCQ *tcq) {
    if (!tcq) return;
    if (tcq->cq) ibv_destroy_cq(tcq->cq);
    if (tcq->comp_channel) ibv_destroy_comp_channel(tcq->comp_channel);
    zfree(tcq);
}

static int verbsGetCQFd(rdmaTransportCQ *tcq) {
    return tcq->comp_channel->fd;
}

static int verbsNotifyCQ(rdmaTransportCQ *tcq) {
    return ibv_req_notify_cq(tcq->cq, 0);
}

static int verbsCreateEP(rdmaTransportEP *ep, rdmaTransportDomain *domain,
                          rdmaTransportEPAttr *attr) {
    struct ibv_qp_init_attr init_attr;
    memset(&init_attr, 0, sizeof(init_attr));
    init_attr.cap.max_send_wr = attr->max_send_wr;
    init_attr.cap.max_recv_wr = attr->max_recv_wr;
    init_attr.cap.max_send_sge = attr->max_send_sge;
    init_attr.cap.max_recv_sge = attr->max_recv_sge;
    init_attr.qp_type = IBV_QPT_RC;
    init_attr.send_cq = attr->send_cq->cq;
    init_attr.recv_cq = attr->recv_cq->cq;
    return rdma_create_qp(ep->cm_id, domain->pd, &init_attr);
}

static void verbsDestroyEP(rdmaTransportEP *ep) {
    if (!ep) return;
    if (ep->cm_id && ep->cm_id->qp) {
        ibv_destroy_qp(ep->cm_id->qp);
    }
}

static int verbsQueryDeviceMaxSGE(rdmaTransportEP *ep) {
    struct ibv_device_attr device_attr;
    if (ibv_query_device(ep->cm_id->verbs, &device_attr)) {
        return -1;
    }
    return device_attr.max_sge;
}

static rdmaTransportMR *verbsRegMR(rdmaTransportDomain *domain, void *buf,
                                    size_t len, int access_flags) {
    rdmaTransportMR *tmr = zmalloc(sizeof(*tmr));
    tmr->mr = ibv_reg_mr(domain->pd, buf, len, verbsAccessFlags(access_flags));
    if (!tmr->mr) {
        zfree(tmr);
        return NULL;
    }
    return tmr;
}

static void verbsDeregMR(rdmaTransportMR *tmr) {
    if (!tmr) return;
    if (tmr->mr) ibv_dereg_mr(tmr->mr);
    zfree(tmr);
}

static uint32_t verbsMRLkey(rdmaTransportMR *tmr) {
    return tmr->mr->lkey;
}

static uint32_t verbsMRRkey(rdmaTransportMR *tmr) {
    return tmr->mr->rkey;
}

static int verbsPostRecv(rdmaTransportEP *ep, void *buf, size_t len,
                          rdmaTransportMR *mr, uint64_t wr_id) {
    struct ibv_sge sge;
    struct ibv_recv_wr recv_wr, *bad_wr;

    sge.addr = (uint64_t)(uintptr_t)buf;
    sge.length = len;
    sge.lkey = mr->mr->lkey;

    memset(&recv_wr, 0, sizeof(recv_wr));
    recv_wr.wr_id = wr_id;
    recv_wr.sg_list = &sge;
    recv_wr.num_sge = 1;
    recv_wr.next = NULL;

    return ibv_post_recv(ep->cm_id->qp, &recv_wr, &bad_wr);
}

static int verbsPostSend(rdmaTransportEP *ep, void *buf, size_t len,
                          rdmaTransportMR *mr, uint64_t wr_id, int signaled) {
    struct ibv_sge sge;
    struct ibv_send_wr send_wr, *bad_wr;

    sge.addr = (uint64_t)(uintptr_t)buf;
    sge.length = len;
    sge.lkey = mr->mr->lkey;

    memset(&send_wr, 0, sizeof(send_wr));
    send_wr.sg_list = &sge;
    send_wr.num_sge = 1;
    send_wr.wr_id = wr_id;
    send_wr.opcode = IBV_WR_SEND;
    send_wr.send_flags = signaled ? IBV_SEND_SIGNALED : 0;
    send_wr.next = NULL;

    return ibv_post_send(ep->cm_id->qp, &send_wr, &bad_wr);
}

static int verbsPostRdmaWriteImm(rdmaTransportEP *ep,
                                   void *local_buf, size_t len,
                                   rdmaTransportMR *local_mr,
                                   uint64_t remote_addr, uint32_t rkey,
                                   uint32_t imm_data, uint64_t wr_id,
                                   int signaled) {
    struct ibv_sge sge;
    struct ibv_send_wr send_wr, *bad_wr;

    sge.addr = (uint64_t)(uintptr_t)local_buf;
    sge.lkey = local_mr->mr->lkey;
    sge.length = len;

    memset(&send_wr, 0, sizeof(send_wr));
    send_wr.sg_list = &sge;
    send_wr.num_sge = 1;
    send_wr.opcode = IBV_WR_RDMA_WRITE_WITH_IMM;
    send_wr.send_flags = signaled ? IBV_SEND_SIGNALED : 0;
    send_wr.imm_data = htonl(imm_data);
    send_wr.wr.rdma.remote_addr = remote_addr;
    send_wr.wr.rdma.rkey = rkey;
    send_wr.wr_id = wr_id;
    send_wr.next = NULL;

    return ibv_post_send(ep->cm_id->qp, &send_wr, &bad_wr);
}

static int verbsGetCQEvent(rdmaTransportCQ *tcq) {
    struct ibv_cq *ev_cq = NULL;
    void *ev_ctx = NULL;

    if (ibv_get_cq_event(tcq->comp_channel, &ev_cq, &ev_ctx) < 0) {
        if (errno != EAGAIN) return -1;
        return 0;
    }
    ibv_ack_cq_events(tcq->cq, 1);
    if (ibv_req_notify_cq(ev_cq, 0)) {
        return -1;
    }
    return 1;
}

static void verbsAckCQEvent(rdmaTransportCQ *tcq) {
    UNUSED(tcq);
    /* already acked in getCQEvent */
}

static int verbsPollCQ(rdmaTransportCQ *tcq, rdmaTransportWC *wc) {
    struct ibv_wc ibwc = {0};
    int ret = ibv_poll_cq(tcq->cq, 1, &ibwc);
    if (ret < 0) return -1;
    if (ret == 0) return 0;

    wc->status = (ibwc.status != IBV_WC_SUCCESS) ? ibwc.status : 0;
    wc->wr_id = ibwc.wr_id;
    wc->byte_len = ibwc.byte_len;
    wc->imm_data = ntohl(ibwc.imm_data);

    switch (ibwc.opcode) {
    case IBV_WC_RECV: wc->opcode = RDMA_TRANSPORT_WC_RECV; break;
    case IBV_WC_RECV_RDMA_WITH_IMM: wc->opcode = RDMA_TRANSPORT_WC_RECV_RDMA_WITH_IMM; break;
    case IBV_WC_RDMA_WRITE: wc->opcode = RDMA_TRANSPORT_WC_RDMA_WRITE; break;
    case IBV_WC_SEND: wc->opcode = RDMA_TRANSPORT_WC_SEND; break;
    default: wc->opcode = RDMA_TRANSPORT_WC_UNKNOWN; break;
    }

    return 1;
}

static const char *verbsWCStatusStr(int status) {
    return ibv_wc_status_str(status);
}

/* --- Connection Management (Server) --- */

static rdmaTransportEQ *verbsCreateEventChannel(void) {
    rdmaTransportEQ *teq = zmalloc(sizeof(*teq));
    teq->cm_channel = rdma_create_event_channel();
    teq->pending_event = NULL;
    if (!teq->cm_channel) {
        zfree(teq);
        return NULL;
    }
    return teq;
}

static void verbsDestroyEventChannel(rdmaTransportEQ *teq) {
    if (!teq) return;
    if (teq->pending_event) rdma_ack_cm_event(teq->pending_event);
    if (teq->cm_channel) rdma_destroy_event_channel(teq->cm_channel);
    zfree(teq);
}

static int verbsGetEQFd(rdmaTransportEQ *teq) {
    return teq->cm_channel->fd;
}

static rdmaTransportPEP *verbsCreateListenEP(rdmaTransportEQ *eq, int af_only) {
    UNUSED(af_only);
    rdmaTransportPEP *pep = zmalloc(sizeof(*pep));
    pep->cm_channel = eq->cm_channel;

    if (rdma_create_id(eq->cm_channel, &pep->cm_id, NULL, RDMA_PS_TCP)) {
        zfree(pep);
        return NULL;
    }

    int afonly = 1;
    rdma_set_option(pep->cm_id, RDMA_OPTION_ID, RDMA_OPTION_ID_AFONLY, &afonly, sizeof(afonly));
    return pep;
}

static void verbsDestroyListenEP(rdmaTransportPEP *pep) {
    if (!pep) return;
    if (pep->cm_id) rdma_destroy_id(pep->cm_id);
    zfree(pep);
}

static int verbsBindListen(rdmaTransportPEP *pep, struct sockaddr *addr, size_t addrlen) {
    UNUSED(addrlen);
    return rdma_bind_addr(pep->cm_id, addr);
}

static int verbsListenEP(rdmaTransportPEP *pep, int backlog) {
    return rdma_listen(pep->cm_id, backlog);
}

static rdmaTransportCMEvent verbsMapCMEvent(enum rdma_cm_event_type type) {
    switch (type) {
    case RDMA_CM_EVENT_CONNECT_REQUEST: return RDMA_TRANSPORT_CM_CONNECT_REQUEST;
    case RDMA_CM_EVENT_ESTABLISHED: return RDMA_TRANSPORT_CM_ESTABLISHED;
    case RDMA_CM_EVENT_ADDR_RESOLVED: return RDMA_TRANSPORT_CM_ADDR_RESOLVED;
    case RDMA_CM_EVENT_ROUTE_RESOLVED: return RDMA_TRANSPORT_CM_ROUTE_RESOLVED;
    case RDMA_CM_EVENT_REJECTED: return RDMA_TRANSPORT_CM_REJECTED;
    case RDMA_CM_EVENT_UNREACHABLE:
    case RDMA_CM_EVENT_ADDR_ERROR:
    case RDMA_CM_EVENT_ROUTE_ERROR:
    case RDMA_CM_EVENT_CONNECT_ERROR:
    case RDMA_CM_EVENT_ADDR_CHANGE:
    case RDMA_CM_EVENT_DISCONNECTED:
    case RDMA_CM_EVENT_TIMEWAIT_EXIT: return RDMA_TRANSPORT_CM_DISCONNECTED;
    default: return RDMA_TRANSPORT_CM_IGNORED;
    }
}

static int verbsGetCMEvent(rdmaTransportEQ *eq, rdmaTransportCMEventData *ev_data) {
    struct rdma_cm_event *ev;
    int ret;

    /* Ack any previously pending event */
    if (eq->pending_event) {
        rdma_ack_cm_event(eq->pending_event);
        eq->pending_event = NULL;
    }

    ret = rdma_get_cm_event(eq->cm_channel, &ev);
    if (ret) {
        if (errno == EAGAIN) return 0;
        return -1;
    }

    eq->pending_event = ev;
    ev_data->event = verbsMapCMEvent(ev->event);

    /* Wrap the cm_id as an EP for all event types that reference a connection.
     * For CONNECT_REQUEST, this is a new cm_id; for ESTABLISHED/DISCONNECTED,
     * it's an existing one with context already set. */
    if (ev->id) {
        rdmaTransportEP *new_ep = zmalloc(sizeof(*new_ep));
        new_ep->cm_id = ev->id;
        ev_data->new_ep = new_ep;
    } else {
        ev_data->new_ep = NULL;
    }

    /* Extract peer address */
    if (ev->id) {
        struct sockaddr *dst = &ev->id->route.addr.dst_addr;
        if (dst->sa_family == AF_INET) {
            memcpy(&ev_data->peer_addr, dst, sizeof(struct sockaddr_in));
        } else if (dst->sa_family == AF_INET6) {
            memcpy(&ev_data->peer_addr, dst, sizeof(struct sockaddr_in6));
        }
    }

    return 1;
}

static int verbsAckCMEvent(rdmaTransportEQ *eq) {
    if (eq->pending_event) {
        int ret = rdma_ack_cm_event(eq->pending_event);
        eq->pending_event = NULL;
        return ret;
    }
    return 0;
}

static int verbsAccept(rdmaTransportEP *ep, rdmaTransportConnParam *param) {
    struct rdma_conn_param conn_param = {0};
    conn_param.responder_resources = param->responder_resources;
    conn_param.initiator_depth = param->initiator_depth;
    conn_param.retry_count = param->retry_count;
    conn_param.rnr_retry_count = param->rnr_retry_count;
    return rdma_accept(ep->cm_id, &conn_param);
}

static int verbsReject(rdmaTransportEP *ep) {
    return rdma_reject(ep->cm_id, NULL, 0);
}

/* --- Connection Management (Client) --- */

static rdmaTransportEP *verbsCreateClientEP(rdmaTransportEQ *eq) {
    rdmaTransportEP *ep = zmalloc(sizeof(*ep));
    if (rdma_create_id(eq->cm_channel, &ep->cm_id, NULL, RDMA_PS_TCP)) {
        zfree(ep);
        return NULL;
    }
    return ep;
}

static int verbsResolveAddr(rdmaTransportEP *ep, struct sockaddr *addr, int timeout_ms) {
    return rdma_resolve_addr(ep->cm_id, NULL, addr, timeout_ms);
}

static int verbsResolveRoute(rdmaTransportEP *ep, int timeout_ms) {
    return rdma_resolve_route(ep->cm_id, timeout_ms);
}

static int verbsConnect(rdmaTransportEP *ep, rdmaTransportConnParam *param) {
    struct rdma_conn_param conn_param = {0};
    conn_param.responder_resources = param->responder_resources;
    conn_param.initiator_depth = param->initiator_depth;
    conn_param.retry_count = param->retry_count;
    conn_param.rnr_retry_count = param->rnr_retry_count;
    return rdma_connect(ep->cm_id, &conn_param);
}

static int verbsDisconnect(rdmaTransportEP *ep) {
    return rdma_disconnect(ep->cm_id);
}

static int verbsGetLocalAddr(rdmaTransportEP *ep, struct sockaddr_storage *addr) {
    struct sockaddr *sa = rdma_get_local_addr(ep->cm_id);
    if (!sa) return -1;
    if (sa->sa_family == AF_INET) {
        memcpy(addr, sa, sizeof(struct sockaddr_in));
    } else if (sa->sa_family == AF_INET6) {
        memcpy(addr, sa, sizeof(struct sockaddr_in6));
    } else {
        return -1;
    }
    return 0;
}

static int verbsGetPeerAddr(rdmaTransportEP *ep, struct sockaddr_storage *addr) {
    struct sockaddr *sa = rdma_get_peer_addr(ep->cm_id);
    if (!sa) return -1;
    if (sa->sa_family == AF_INET) {
        memcpy(addr, sa, sizeof(struct sockaddr_in));
    } else if (sa->sa_family == AF_INET6) {
        memcpy(addr, sa, sizeof(struct sockaddr_in6));
    } else {
        return -1;
    }
    return 0;
}

static int verbsGetPeerAddrFromRequest(rdmaTransportCMEventData *ev,
                                        struct sockaddr_storage *addr) {
    memcpy(addr, &ev->peer_addr, sizeof(*addr));
    return 0;
}

static void verbsSetEPContext(rdmaTransportEP *ep, void *ctx) {
    ep->cm_id->context = ctx;
}

static void *verbsGetEPContext(rdmaTransportEP *ep) {
    return ep->cm_id->context;
}

/* -------------------------------------------------------------------------
 * Operations table
 * ------------------------------------------------------------------------- */
const rdmaTransportOps rdmaTransportVerbsOps = {
    .name = "verbs",

    .init = verbsInit,
    .cleanup = verbsCleanup,

    .alloc_domain = verbsAllocDomain,
    .free_domain = verbsFreeDomain,

    .create_cq = verbsCreateCQ,
    .destroy_cq = verbsDestroyCQ,
    .get_cq_fd = verbsGetCQFd,
    .notify_cq = verbsNotifyCQ,

    .create_ep = verbsCreateEP,
    .destroy_ep = verbsDestroyEP,
    .query_device_max_sge = verbsQueryDeviceMaxSGE,

    .reg_mr = verbsRegMR,
    .dereg_mr = verbsDeregMR,
    .mr_lkey = verbsMRLkey,
    .mr_rkey = verbsMRRkey,

    .post_recv = verbsPostRecv,
    .post_send = verbsPostSend,
    .post_rdma_write_imm = verbsPostRdmaWriteImm,

    .get_cq_event = verbsGetCQEvent,
    .ack_cq_event = verbsAckCQEvent,
    .poll_cq = verbsPollCQ,
    .wc_status_str = verbsWCStatusStr,

    .create_event_channel = verbsCreateEventChannel,
    .destroy_event_channel = verbsDestroyEventChannel,
    .get_eq_fd = verbsGetEQFd,

    .create_listen_ep = verbsCreateListenEP,
    .destroy_listen_ep = verbsDestroyListenEP,
    .bind_listen = verbsBindListen,
    .listen_ep = verbsListenEP,

    .get_cm_event = verbsGetCMEvent,
    .ack_cm_event = verbsAckCMEvent,

    .accept = verbsAccept,
    .reject = verbsReject,

    .create_client_ep = verbsCreateClientEP,
    .resolve_addr = verbsResolveAddr,
    .resolve_route = verbsResolveRoute,
    .connect = verbsConnect,

    .disconnect = verbsDisconnect,
    .get_local_addr = verbsGetLocalAddr,
    .get_peer_addr = verbsGetPeerAddr,
    .get_peer_addr_from_request = verbsGetPeerAddrFromRequest,

    .set_ep_context = verbsSetEPContext,
    .get_ep_context = verbsGetEPContext,
};

#endif /* RDMA_TRANSPORT_VERBS_H */
