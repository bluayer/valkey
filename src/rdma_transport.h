/* ==========================================================================
 * rdma_transport.h - Transport provider abstraction for RDMA backends.
 * --------------------------------------------------------------------------
 * This header defines a provider-agnostic interface that allows the RDMA
 * connection layer (rdma.c) to work with different transport backends:
 *   - ibverbs/rdma_cm  (traditional, USE_RDMA_VERBS)
 *   - libfabric/OFI    (USE_RDMA_FABRIC)
 *
 * Copyright (c) Valkey Contributors
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * ==========================================================================
 */

#ifndef RDMA_TRANSPORT_H
#define RDMA_TRANSPORT_H

#include <stdint.h>
#include <stddef.h>

/* -------------------------------------------------------------------------
 * Opaque handle types - each backend defines the concrete types
 * ------------------------------------------------------------------------- */

/* Protection domain / fabric domain */
typedef struct rdmaTransportDomain rdmaTransportDomain;

/* Completion queue */
typedef struct rdmaTransportCQ rdmaTransportCQ;

/* Memory region */
typedef struct rdmaTransportMR rdmaTransportMR;

/* Endpoint (QP in verbs, fid_ep in fabric) */
typedef struct rdmaTransportEP rdmaTransportEP;

/* Event channel for connection management */
typedef struct rdmaTransportEQ rdmaTransportEQ;

/* Passive (listening) endpoint */
typedef struct rdmaTransportPEP rdmaTransportPEP;

/* -------------------------------------------------------------------------
 * Access flags for memory registration
 * ------------------------------------------------------------------------- */
#define RDMA_TRANSPORT_ACCESS_LOCAL_WRITE   (1 << 0)
#define RDMA_TRANSPORT_ACCESS_REMOTE_READ   (1 << 1)
#define RDMA_TRANSPORT_ACCESS_REMOTE_WRITE  (1 << 2)

/* -------------------------------------------------------------------------
 * Completion entry - unified work completion representation
 * ------------------------------------------------------------------------- */
typedef enum rdmaTransportWCOpcode {
    RDMA_TRANSPORT_WC_RECV = 0,
    RDMA_TRANSPORT_WC_RECV_RDMA_WITH_IMM,
    RDMA_TRANSPORT_WC_RDMA_WRITE,
    RDMA_TRANSPORT_WC_SEND,
    RDMA_TRANSPORT_WC_UNKNOWN,
} rdmaTransportWCOpcode;

typedef struct rdmaTransportWC {
    rdmaTransportWCOpcode opcode;
    int status;          /* 0 = success, non-zero = error */
    uint64_t wr_id;      /* work request identifier */
    uint32_t byte_len;   /* bytes transferred */
    uint32_t imm_data;   /* immediate data (host byte order) */
} rdmaTransportWC;

/* -------------------------------------------------------------------------
 * CM (connection management) event types
 * ------------------------------------------------------------------------- */
typedef enum rdmaTransportCMEvent {
    RDMA_TRANSPORT_CM_CONNECT_REQUEST = 0,
    RDMA_TRANSPORT_CM_ESTABLISHED,
    RDMA_TRANSPORT_CM_DISCONNECTED,
    RDMA_TRANSPORT_CM_ADDR_RESOLVED,
    RDMA_TRANSPORT_CM_ROUTE_RESOLVED,
    RDMA_TRANSPORT_CM_REJECTED,
    RDMA_TRANSPORT_CM_ERROR,
    RDMA_TRANSPORT_CM_IGNORED,
} rdmaTransportCMEvent;

typedef struct rdmaTransportCMEventData {
    rdmaTransportCMEvent event;
    /* For CONNECT_REQUEST: the new endpoint for the incoming connection */
    rdmaTransportEP *new_ep;
    /* For address extraction */
    struct sockaddr_storage peer_addr;
} rdmaTransportCMEventData;

/* -------------------------------------------------------------------------
 * Connection parameters
 * ------------------------------------------------------------------------- */
typedef struct rdmaTransportConnParam {
    uint8_t responder_resources;
    uint8_t initiator_depth;
    uint8_t retry_count;
    uint8_t rnr_retry_count;
} rdmaTransportConnParam;

/* -------------------------------------------------------------------------
 * Endpoint attributes (QP init attributes equivalent)
 * ------------------------------------------------------------------------- */
typedef struct rdmaTransportEPAttr {
    uint32_t max_send_wr;
    uint32_t max_recv_wr;
    uint32_t max_send_sge;
    uint32_t max_recv_sge;
    rdmaTransportCQ *send_cq;
    rdmaTransportCQ *recv_cq;
} rdmaTransportEPAttr;

/* -------------------------------------------------------------------------
 * Transport provider operations - function table
 * ------------------------------------------------------------------------- */
typedef struct rdmaTransportOps {
    const char *name; /* "verbs" or "fabric" */

    /* --- Initialization / Cleanup --- */
    int (*init)(void);
    void (*cleanup)(void);

    /* --- Resource management --- */
    rdmaTransportDomain *(*alloc_domain)(rdmaTransportEP *ep);
    void (*free_domain)(rdmaTransportDomain *domain);

    rdmaTransportCQ *(*create_cq)(rdmaTransportEP *ep, int cq_size,
                                  rdmaTransportDomain *domain, int comp_vector);
    void (*destroy_cq)(rdmaTransportCQ *cq);
    int (*get_cq_fd)(rdmaTransportCQ *cq);
    int (*notify_cq)(rdmaTransportCQ *cq);

    /* --- Endpoint (QP) --- */
    int (*create_ep)(rdmaTransportEP *ep, rdmaTransportDomain *domain,
                     rdmaTransportEPAttr *attr);
    void (*destroy_ep)(rdmaTransportEP *ep);
    int (*query_device_max_sge)(rdmaTransportEP *ep);

    /* --- Memory registration --- */
    rdmaTransportMR *(*reg_mr)(rdmaTransportDomain *domain, void *buf,
                               size_t len, int access_flags);
    void (*dereg_mr)(rdmaTransportMR *mr);
    uint32_t (*mr_lkey)(rdmaTransportMR *mr);
    uint32_t (*mr_rkey)(rdmaTransportMR *mr);

    /* --- Data path --- */
    int (*post_recv)(rdmaTransportEP *ep, void *buf, size_t len,
                     rdmaTransportMR *mr, uint64_t wr_id);
    int (*post_send)(rdmaTransportEP *ep, void *buf, size_t len,
                     rdmaTransportMR *mr, uint64_t wr_id, int signaled);
    int (*post_rdma_write_imm)(rdmaTransportEP *ep,
                               void *local_buf, size_t len,
                               rdmaTransportMR *local_mr,
                               uint64_t remote_addr, uint32_t rkey,
                               uint32_t imm_data, uint64_t wr_id,
                               int signaled);

    /* --- Completion handling --- */
    /* Returns: 1 if got CQ event, 0 if EAGAIN, -1 on error */
    int (*get_cq_event)(rdmaTransportCQ *cq);
    void (*ack_cq_event)(rdmaTransportCQ *cq);
    /* Returns: 1 if got WC, 0 if empty, -1 on error */
    int (*poll_cq)(rdmaTransportCQ *cq, rdmaTransportWC *wc);
    const char *(*wc_status_str)(int status);

    /* --- Connection management (server) --- */
    rdmaTransportEQ *(*create_event_channel)(void);
    void (*destroy_event_channel)(rdmaTransportEQ *eq);
    int (*get_eq_fd)(rdmaTransportEQ *eq);

    rdmaTransportPEP *(*create_listen_ep)(rdmaTransportEQ *eq, int af_only);
    void (*destroy_listen_ep)(rdmaTransportPEP *pep);
    int (*bind_listen)(rdmaTransportPEP *pep, struct sockaddr *addr, size_t addrlen);
    int (*listen_ep)(rdmaTransportPEP *pep, int backlog);

    /* Get CM event from listener EQ. Returns event type. */
    int (*get_cm_event)(rdmaTransportEQ *eq, rdmaTransportCMEventData *ev_data);
    int (*ack_cm_event)(rdmaTransportEQ *eq);

    int (*accept)(rdmaTransportEP *ep, rdmaTransportConnParam *param);
    int (*reject)(rdmaTransportEP *ep);

    /* --- Connection management (client) --- */
    rdmaTransportEP *(*create_client_ep)(rdmaTransportEQ *eq);
    int (*resolve_addr)(rdmaTransportEP *ep, struct sockaddr *addr, int timeout_ms);
    int (*resolve_route)(rdmaTransportEP *ep, int timeout_ms);
    int (*connect)(rdmaTransportEP *ep, rdmaTransportConnParam *param);

    /* --- Connection management (common) --- */
    int (*disconnect)(rdmaTransportEP *ep);
    int (*get_local_addr)(rdmaTransportEP *ep, struct sockaddr_storage *addr);
    int (*get_peer_addr)(rdmaTransportEP *ep, struct sockaddr_storage *addr);
    int (*get_peer_addr_from_request)(rdmaTransportCMEventData *ev,
                                      struct sockaddr_storage *addr);

    /* Context storage on endpoint */
    void (*set_ep_context)(rdmaTransportEP *ep, void *ctx);
    void *(*get_ep_context)(rdmaTransportEP *ep);

} rdmaTransportOps;

/* -------------------------------------------------------------------------
 * Provider registration
 * ------------------------------------------------------------------------- */
extern const rdmaTransportOps *rdmaTransportGetOps(void);

#ifdef USE_RDMA_VERBS
extern const rdmaTransportOps rdmaTransportVerbsOps;
#endif

#ifdef USE_RDMA_FABRIC
extern const rdmaTransportOps rdmaTransportFabricOps;
#endif

#endif /* RDMA_TRANSPORT_H */
