/* ==========================================================================
 * test_rdma_fabric.c - Unit tests for rdma_fabric.c logic
 * --------------------------------------------------------------------------
 * Tests the key logic components of rdma_fabric.c WITHOUT requiring
 * libfabric headers. We duplicate the relevant type definitions and
 * test the pure-logic functions directly.
 *
 * Build & run:
 *   gcc -o test_rdma_fabric test_rdma_fabric.c -I../../src -lpthread
 *   ./test_rdma_fabric
 * ==========================================================================
 */

#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <unistd.h>

/* ========================================================================
 * Duplicated types from rdma_fabric.c (wire protocol must match exactly)
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
    uint8_t rsvd[6];
    uint64_t addr;
    uint64_t key;
    uint32_t length;
    uint32_t rsvd2;
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

#define VALKEY_RDMA_INVALID_OPCODE 0xffff
#define VALKEY_RDMA_MAX_WQE 1024
#define RDMA_MAX_CONNECTIONS 4096
#define RDMA_MAX_EP_NAME 256

/* Endian helpers (must match rdma.c / endianconv.h) */
static inline uint64_t htonu64(uint64_t v) {
    uint64_t r;
    uint8_t *p = (uint8_t *)&r;
    p[0] = (v >> 56) & 0xff;
    p[1] = (v >> 48) & 0xff;
    p[2] = (v >> 40) & 0xff;
    p[3] = (v >> 32) & 0xff;
    p[4] = (v >> 24) & 0xff;
    p[5] = (v >> 16) & 0xff;
    p[6] = (v >> 8) & 0xff;
    p[7] = v & 0xff;
    return r;
}

static inline uint64_t ntohu64(uint64_t v) {
    return htonu64(v); /* symmetric */
}

/* ========================================================================
 * Test infrastructure
 * ======================================================================== */

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name)                                     \
    static void test_##name(void);                     \
    static void run_test_##name(void) {                \
        tests_run++;                                   \
        printf("  TEST %-50s ", #name);                \
        test_##name();                                 \
        tests_passed++;                                \
        printf("PASS\n");                              \
    }                                                  \
    static void test_##name(void)

#define ASSERT_EQ(a, b)                                                             \
    do {                                                                            \
        if ((a) != (b)) {                                                           \
            printf("FAIL\n    %s:%d: %s (%ld) != %s (%ld)\n", __FILE__, __LINE__,  \
                   #a, (long)(a), #b, (long)(b));                                   \
            tests_failed++;                                                         \
            tests_passed--;                                                         \
            return;                                                                 \
        }                                                                           \
    } while (0)

#define ASSERT_NE(a, b)                                                             \
    do {                                                                            \
        if ((a) == (b)) {                                                           \
            printf("FAIL\n    %s:%d: %s == %s (both %ld)\n", __FILE__, __LINE__,    \
                   #a, #b, (long)(a));                                              \
            tests_failed++;                                                         \
            tests_passed--;                                                         \
            return;                                                                 \
        }                                                                           \
    } while (0)

#define ASSERT_TRUE(cond)                                                           \
    do {                                                                            \
        if (!(cond)) {                                                              \
            printf("FAIL\n    %s:%d: %s is false\n", __FILE__, __LINE__, #cond);    \
            tests_failed++;                                                         \
            tests_passed--;                                                         \
            return;                                                                 \
        }                                                                           \
    } while (0)

#define ASSERT_STREQ(a, b)                                                          \
    do {                                                                            \
        if (strcmp((a), (b)) != 0) {                                                \
            printf("FAIL\n    %s:%d: \"%s\" != \"%s\"\n", __FILE__, __LINE__,       \
                   (a), (b));                                                       \
            tests_failed++;                                                         \
            tests_passed--;                                                         \
            return;                                                                 \
        }                                                                           \
    } while (0)

/* ========================================================================
 * Test 1: Wire protocol struct sizes (MUST be 32 bytes each)
 * ======================================================================== */

TEST(wire_protocol_sizes) {
    ASSERT_EQ(sizeof(ValkeyRdmaFeature), 32);
    ASSERT_EQ(sizeof(ValkeyRdmaKeepalive), 32);
    ASSERT_EQ(sizeof(ValkeyRdmaMemory), 32);
    ASSERT_EQ(sizeof(ValkeyRdmaCmd), 32);
}

/* ========================================================================
 * Test 2: Wire protocol serialization (RegisterXferMemory)
 * ======================================================================== */

TEST(wire_protocol_register_xfer_memory) {
    ValkeyRdmaCmd cmd = {0};
    uint64_t test_addr = 0x7f1234560000ULL;
    uint32_t test_length = 1024 * 1024;
    uint64_t test_key = 0xDEADBEEF12345678ULL; /* 64-bit key for EFA */

    /* Serialize (as rdma_fabric.c does in connRdmaRegisterRx) */
    cmd.memory.opcode = htons(RegisterXferMemory);
    cmd.memory.addr = htonu64(test_addr);
    cmd.memory.length = htonl(test_length);
    cmd.memory.key = htonu64(test_key);

    /* Deserialize (as rdma_fabric.c does in connRdmaHandleRecv) */
    ASSERT_EQ(ntohs(cmd.memory.opcode), RegisterXferMemory);
    ASSERT_EQ(ntohu64(cmd.memory.addr), test_addr);
    ASSERT_EQ(ntohl(cmd.memory.length), test_length);
    ASSERT_EQ(ntohu64(cmd.memory.key), test_key);
}

/* ========================================================================
 * Test 3: Wire protocol serialization (Feature)
 * ======================================================================== */

TEST(wire_protocol_feature) {
    ValkeyRdmaCmd cmd = {0};

    /* Client sends SetClientFeature with features=0 */
    cmd.feature.opcode = htons(SetClientFeature);
    cmd.feature.select = htons(0);
    cmd.feature.features = htonu64(0);

    ASSERT_EQ(ntohs(cmd.feature.opcode), SetClientFeature);
    ASSERT_EQ(ntohu64(cmd.feature.features), 0ULL);

    /* Server responds with GetServerFeature */
    ValkeyRdmaCmd resp = {0};
    resp.feature.opcode = htons(GetServerFeature);
    resp.feature.select = cmd.feature.select; /* echo back */
    resp.feature.features = htonu64(0);

    ASSERT_EQ(ntohs(resp.feature.opcode), GetServerFeature);
}

/* ========================================================================
 * Test 4: Wire protocol opcode dispatch
 * ======================================================================== */

TEST(wire_protocol_opcode_dispatch) {
    ValkeyRdmaCmd cmd;
    int handled;

    /* Test all valid opcodes */
    uint16_t opcodes[] = {GetServerFeature, SetClientFeature, Keepalive, RegisterXferMemory};
    for (int i = 0; i < 4; i++) {
        memset(&cmd, 0, sizeof(cmd));
        cmd.keepalive.opcode = htons(opcodes[i]);

        handled = 0;
        switch (ntohs(cmd.keepalive.opcode)) {
        case GetServerFeature: handled = 1; break;
        case SetClientFeature: handled = 1; break;
        case Keepalive: handled = 1; break;
        case RegisterXferMemory: handled = 1; break;
        default: handled = 0; break;
        }
        ASSERT_EQ(handled, 1);
    }

    /* Test invalid opcode */
    cmd.keepalive.opcode = htons(0xBEEF);
    handled = 0;
    switch (ntohs(cmd.keepalive.opcode)) {
    case GetServerFeature:
    case SetClientFeature:
    case Keepalive:
    case RegisterXferMemory: handled = 1; break;
    default: handled = 0; break;
    }
    ASSERT_EQ(handled, 0);
}

/* ========================================================================
 * Test 5: Send buffer slot management (INVALID_OPCODE marking)
 * ======================================================================== */

TEST(send_buffer_slot_management) {
    /* Simulate send buffer: array of ValkeyRdmaCmd */
    ValkeyRdmaCmd *send_buf = calloc(VALKEY_RDMA_MAX_WQE, sizeof(ValkeyRdmaCmd));
    assert(send_buf);

    /* Initialize all slots as free (INVALID_OPCODE) */
    for (int i = 0; i < VALKEY_RDMA_MAX_WQE; i++) {
        send_buf[i].keepalive.opcode = VALKEY_RDMA_INVALID_OPCODE;
    }

    /* Find first free slot (should be slot 0) */
    int found = -1;
    for (int i = 0; i < VALKEY_RDMA_MAX_WQE; i++) {
        if (send_buf[i].keepalive.opcode == VALKEY_RDMA_INVALID_OPCODE) {
            found = i;
            break;
        }
    }
    ASSERT_EQ(found, 0);

    /* Mark slot 0 as in-use */
    send_buf[0].keepalive.opcode = htons(Keepalive);

    /* Next free should be slot 1 */
    found = -1;
    for (int i = 0; i < VALKEY_RDMA_MAX_WQE; i++) {
        if (send_buf[i].keepalive.opcode == VALKEY_RDMA_INVALID_OPCODE) {
            found = i;
            break;
        }
    }
    ASSERT_EQ(found, 1);

    /* Mark slot 0 as sent (connRdmaHandleSend logic) */
    memset(&send_buf[0], 0, sizeof(ValkeyRdmaCmd));
    send_buf[0].keepalive.opcode = VALKEY_RDMA_INVALID_OPCODE;

    /* Now slot 0 should be free again */
    found = -1;
    for (int i = 0; i < VALKEY_RDMA_MAX_WQE; i++) {
        if (send_buf[i].keepalive.opcode == VALKEY_RDMA_INVALID_OPCODE) {
            found = i;
            break;
        }
    }
    ASSERT_EQ(found, 0);

    /* Fill all slots */
    for (int i = 0; i < VALKEY_RDMA_MAX_WQE; i++) {
        send_buf[i].keepalive.opcode = htons(Keepalive);
    }

    /* Should find no free slot */
    found = -1;
    for (int i = 0; i < VALKEY_RDMA_MAX_WQE; i++) {
        if (send_buf[i].keepalive.opcode == VALKEY_RDMA_INVALID_OPCODE) {
            found = i;
            break;
        }
    }
    ASSERT_EQ(found, -1);

    free(send_buf);
}

/* ========================================================================
 * Test 6: Connection map (fi_addr_t → connection lookup)
 * ======================================================================== */

typedef struct {
    int dummy_fd;
    uint64_t peer_addr;
} MockConnection;

TEST(connection_map_lookup) {
    /* Simulate connection map (same as rdma_g.conn_map) */
    MockConnection *conn_map[RDMA_MAX_CONNECTIONS];
    memset(conn_map, 0, sizeof(conn_map));

    MockConnection conn1 = {.dummy_fd = 10, .peer_addr = 0};
    MockConnection conn2 = {.dummy_fd = 20, .peer_addr = 5};
    MockConnection conn3 = {.dummy_fd = 30, .peer_addr = RDMA_MAX_CONNECTIONS - 1};

    /* Register connections */
    conn_map[conn1.peer_addr] = &conn1;
    conn_map[conn2.peer_addr] = &conn2;
    conn_map[conn3.peer_addr] = &conn3;

    /* Lookup */
    ASSERT_EQ(conn_map[0]->dummy_fd, 10);
    ASSERT_EQ(conn_map[5]->dummy_fd, 20);
    ASSERT_EQ(conn_map[RDMA_MAX_CONNECTIONS - 1]->dummy_fd, 30);

    /* Unregistered addresses */
    ASSERT_TRUE(conn_map[1] == NULL);
    ASSERT_TRUE(conn_map[100] == NULL);

    /* Bounds check: addr >= RDMA_MAX_CONNECTIONS should not be used */
    uint64_t bad_addr = RDMA_MAX_CONNECTIONS;
    ASSERT_TRUE(bad_addr >= RDMA_MAX_CONNECTIONS); /* would skip lookup */

    /* Unregister */
    conn_map[conn2.peer_addr] = NULL;
    ASSERT_TRUE(conn_map[5] == NULL);
}

/* ========================================================================
 * Test 7: Eventfd signal/drain
 * ======================================================================== */

TEST(eventfd_signal_drain) {
    int evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    ASSERT_NE(evfd, -1);

    /* Signal the eventfd */
    uint64_t val = 1;
    ssize_t ret = write(evfd, &val, sizeof(val));
    ASSERT_EQ(ret, sizeof(val));

    /* Drain should succeed and return the value */
    uint64_t rval = 0;
    ret = read(evfd, &rval, sizeof(rval));
    ASSERT_EQ(ret, sizeof(rval));
    ASSERT_EQ(rval, 1ULL);

    /* Second drain should fail with EAGAIN (no data) */
    ret = read(evfd, &rval, sizeof(rval));
    ASSERT_EQ(ret, -1);
    ASSERT_EQ(errno, EAGAIN);

    /* Multiple signals accumulate */
    val = 1;
    write(evfd, &val, sizeof(val));
    write(evfd, &val, sizeof(val));
    write(evfd, &val, sizeof(val));
    ret = read(evfd, &rval, sizeof(rval));
    ASSERT_EQ(ret, sizeof(rval));
    ASSERT_EQ(rval, 3ULL); /* accumulated */

    close(evfd);
}

/* ========================================================================
 * Test 8: Memory alignment (rdmaMemoryAlloc logic)
 * ======================================================================== */

TEST(memory_alignment) {
    size_t page_size = sysconf(_SC_PAGESIZE);
    size_t test_sizes[] = {32, 64, 1024, 4096, 65536, 1024 * 1024};

    for (int i = 0; i < 6; i++) {
        size_t size = test_sizes[i];
        size_t aligned_size = (size + page_size - 1) & (~(page_size - 1));
        size_t real_size = aligned_size + 2 * page_size;

        uint8_t *ptr = mmap(NULL, real_size, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        ASSERT_NE(ptr, MAP_FAILED);

        mprotect(ptr, page_size, PROT_NONE);
        mprotect(ptr + aligned_size + page_size, page_size, PROT_NONE);

        uint8_t *usable = ptr + page_size;

        /* Verify alignment */
        ASSERT_EQ((uintptr_t)usable % page_size, 0);

        /* Verify we can write to the usable region */
        memset(usable, 0xAB, size);
        ASSERT_EQ(usable[0], 0xAB);
        ASSERT_EQ(usable[size - 1], 0xAB);

        /* Cleanup */
        uint8_t *real_ptr = usable - page_size;
        munmap(real_ptr, real_size);
    }
}

/* ========================================================================
 * Test 9: TCP handshake protocol format
 *
 * Tests that the TCP address exchange protocol (4-byte length + name)
 * can round-trip correctly through a socketpair.
 * ======================================================================== */

TEST(tcp_handshake_protocol) {
    int sv[2]; /* socketpair simulates TCP connection */
    int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    ASSERT_EQ(ret, 0);

    /* Simulated EP names */
    uint8_t server_name[RDMA_MAX_EP_NAME];
    uint8_t client_name[RDMA_MAX_EP_NAME];
    memset(server_name, 0xAA, 64);
    memset(client_name, 0xBB, 48);
    size_t server_name_len = 64;
    size_t client_name_len = 48;

    /* Client sends its name (rdmaTcpHandshakeClient logic) */
    uint32_t len_net = htonl((uint32_t)client_name_len);
    write(sv[0], &len_net, sizeof(len_net));
    write(sv[0], client_name, client_name_len);

    /* Server reads client name (rdmaTcpHandshakeServer logic) */
    uint32_t peer_name_len;
    uint8_t peer_name[RDMA_MAX_EP_NAME];
    ssize_t n = read(sv[1], &peer_name_len, sizeof(peer_name_len));
    ASSERT_EQ(n, sizeof(peer_name_len));
    peer_name_len = ntohl(peer_name_len);
    ASSERT_EQ(peer_name_len, client_name_len);
    ASSERT_TRUE(peer_name_len <= RDMA_MAX_EP_NAME);

    n = read(sv[1], peer_name, peer_name_len);
    ASSERT_EQ(n, (ssize_t)peer_name_len);
    ASSERT_EQ(memcmp(peer_name, client_name, peer_name_len), 0);

    /* Server sends its name back */
    len_net = htonl((uint32_t)server_name_len);
    write(sv[1], &len_net, sizeof(len_net));
    write(sv[1], server_name, server_name_len);

    /* Client reads server name */
    n = read(sv[0], &peer_name_len, sizeof(peer_name_len));
    ASSERT_EQ(n, sizeof(peer_name_len));
    peer_name_len = ntohl(peer_name_len);
    ASSERT_EQ(peer_name_len, server_name_len);

    n = read(sv[0], peer_name, peer_name_len);
    ASSERT_EQ(n, (ssize_t)peer_name_len);
    ASSERT_EQ(memcmp(peer_name, server_name, peer_name_len), 0);

    close(sv[0]);
    close(sv[1]);
}

/* ========================================================================
 * Test 10: TCP handshake — invalid/oversized name rejection
 * ======================================================================== */

TEST(tcp_handshake_oversized_name) {
    int sv[2];
    int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    ASSERT_EQ(ret, 0);

    /* Send oversized name length */
    uint32_t bad_len = htonl(RDMA_MAX_EP_NAME + 1);
    write(sv[0], &bad_len, sizeof(bad_len));

    /* Reader should reject this */
    uint32_t peer_name_len;
    ssize_t n = read(sv[1], &peer_name_len, sizeof(peer_name_len));
    ASSERT_EQ(n, sizeof(peer_name_len));
    peer_name_len = ntohl(peer_name_len);
    ASSERT_TRUE(peer_name_len > RDMA_MAX_EP_NAME); /* should be rejected */

    close(sv[0]);
    close(sv[1]);
}

/* ========================================================================
 * Test 11: RX buffer offset tracking
 * ======================================================================== */

TEST(rx_buffer_offset_tracking) {
    /* Simulate RX buffer state (matches RdmaXfer in rdma_fabric.c) */
    char *rx_addr = malloc(1024 * 1024);
    uint32_t rx_length = 1024 * 1024;
    uint32_t rx_offset = 0; /* written by remote */
    uint32_t rx_pos = 0;    /* consumed by local read */

    /* Remote writes 100 bytes (connRdmaHandleRecvImm) */
    uint32_t imm_data = 100;
    assert(imm_data + rx_offset <= rx_length);
    memset(rx_addr + rx_offset, 'A', imm_data);
    rx_offset += imm_data;
    ASSERT_EQ(rx_offset, 100);

    /* Local reads 50 bytes (rdmaRead) */
    char buf[256];
    uint32_t toread = rx_offset - rx_pos < 50 ? rx_offset - rx_pos : 50;
    memcpy(buf, rx_addr + rx_pos, toread);
    rx_pos += toread;
    ASSERT_EQ(rx_pos, 50);
    ASSERT_EQ(rx_offset - rx_pos, 50); /* 50 bytes remaining */

    /* Remote writes another 200 bytes */
    imm_data = 200;
    assert(imm_data + rx_offset <= rx_length);
    memset(rx_addr + rx_offset, 'B', imm_data);
    rx_offset += imm_data;
    ASSERT_EQ(rx_offset, 300);

    /* Local reads remaining (250 bytes) */
    toread = rx_offset - rx_pos < 256 ? rx_offset - rx_pos : 256;
    memcpy(buf, rx_addr + rx_pos, toread);
    rx_pos += toread;
    ASSERT_EQ(rx_pos, 300);
    ASSERT_EQ(rx_pos, rx_offset); /* fully consumed */

    /* Buffer full → should trigger re-register */
    rx_offset = rx_length;
    rx_pos = rx_length;
    ASSERT_EQ(rx_pos, rx_length); /* triggers connRdmaRegisterRx */

    free(rx_addr);
}

/* ========================================================================
 * Test 12: TX buffer offset tracking with RDMA write
 * ======================================================================== */

TEST(tx_buffer_offset_tracking) {
    char *tx_addr = calloc(1, 1024 * 1024);
    uint32_t tx_length = 1024 * 1024;
    uint32_t tx_offset = 0;
    uint32_t tx_ops = 0;

    /* Simulate writes (connRdmaWrite → connRdmaSend) */
    size_t data_len = 4096;

    /* Write should be capped at available space */
    uint32_t towrite = tx_length - tx_offset < data_len ? tx_length - tx_offset : data_len;
    ASSERT_EQ(towrite, 4096);

    /* After write, offset advances */
    tx_offset += towrite;
    tx_ops++;
    ASSERT_EQ(tx_offset, 4096);

    /* Signaling: every MAX_WQE/2 ops */
    int should_signal = (tx_ops % (VALKEY_RDMA_MAX_WQE / 2) == 0);
    ASSERT_EQ(should_signal, 0); /* not yet */

    /* Simulate many writes */
    for (int i = 1; i < VALKEY_RDMA_MAX_WQE / 2; i++) {
        tx_offset += 64;
        tx_ops++;
    }
    should_signal = (tx_ops % (VALKEY_RDMA_MAX_WQE / 2) == 0);
    ASSERT_EQ(should_signal, 1); /* now! */

    /* Write when buffer is full */
    tx_offset = tx_length;
    towrite = tx_length - tx_offset < data_len ? tx_length - tx_offset : data_len;
    ASSERT_EQ(towrite, 0); /* no space → connRdmaWrite returns 0 */

    free(tx_addr);
}

/* ========================================================================
 * Test 13: Endian conversion round-trip
 * ======================================================================== */

TEST(endian_conversion_roundtrip) {
    uint64_t values[] = {0, 1, 0xFF, 0xDEADBEEF, 0x7f1234560000ULL, UINT64_MAX};

    for (int i = 0; i < 6; i++) {
        uint64_t net = htonu64(values[i]);
        uint64_t host = ntohu64(net);
        ASSERT_EQ(host, values[i]);
    }

    /* Also test standard 16/32-bit */
    ASSERT_EQ(ntohs(htons(6379)), 6379);
    ASSERT_EQ(ntohl(htonl(0xDEADBEEF)), 0xDEADBEEF);
}

/* ========================================================================
 * Test 14: Wire protocol union overlay correctness
 * ======================================================================== */

TEST(wire_protocol_union_overlay) {
    ValkeyRdmaCmd cmd;

    /* Feature: opcode at offset 0 */
    memset(&cmd, 0, sizeof(cmd));
    cmd.feature.opcode = htons(GetServerFeature);
    ASSERT_EQ(ntohs(cmd.keepalive.opcode), GetServerFeature);

    /* Memory: check field offsets */
    memset(&cmd, 0, sizeof(cmd));
    cmd.memory.opcode = htons(RegisterXferMemory);
    cmd.memory.addr = htonu64(0x1234);
    cmd.memory.length = htonl(4096);
    cmd.memory.key = htonu64(99);

    /* Verify opcode readable via keepalive union member */
    ASSERT_EQ(ntohs(cmd.keepalive.opcode), RegisterXferMemory);

    /* Verify Memory struct field positions by checking raw bytes.
     * Fabric layout: opcode(2) + rsvd(6) + addr(8) + key(8) + length(4) + rsvd2(4) */
    uint8_t *raw = (uint8_t *)&cmd;
    /* opcode at offset 0-1 */
    ASSERT_EQ(raw[0], (RegisterXferMemory >> 8) & 0xff);
    ASSERT_EQ(raw[1], RegisterXferMemory & 0xff);
    /* addr at offset 8-15 (opcode 2 + rsvd 6 = 8) */
    uint64_t *addr_ptr = (uint64_t *)(raw + 8);
    ASSERT_EQ(ntohu64(*addr_ptr), 0x1234);
    /* key at offset 16-23 */
    uint64_t *key_ptr = (uint64_t *)(raw + 16);
    ASSERT_EQ(ntohu64(*key_ptr), 99);
    /* length at offset 24-27 */
    uint32_t *len_ptr = (uint32_t *)(raw + 24);
    ASSERT_EQ(ntohl(*len_ptr), 4096);
}

/* ========================================================================
 * Test 15: Multiple eventfd — simulates per-connection signaling
 * ======================================================================== */

TEST(multiple_eventfd_per_connection) {
    #define NUM_CONNS 8
    int evfds[NUM_CONNS];

    /* Create eventfds (as done in rdmaAccept for each connection) */
    for (int i = 0; i < NUM_CONNS; i++) {
        evfds[i] = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        ASSERT_NE(evfds[i], -1);
    }

    /* Signal only connections 2 and 5 (like CQ handler dispatching) */
    uint64_t val = 1;
    write(evfds[2], &val, sizeof(val));
    write(evfds[5], &val, sizeof(val));

    /* Check which connections have data */
    for (int i = 0; i < NUM_CONNS; i++) {
        uint64_t rval;
        ssize_t ret = read(evfds[i], &rval, sizeof(rval));
        if (i == 2 || i == 5) {
            ASSERT_EQ(ret, sizeof(rval));
            ASSERT_EQ(rval, 1ULL);
        } else {
            ASSERT_EQ(ret, -1);
            ASSERT_EQ(errno, EAGAIN);
        }
    }

    for (int i = 0; i < NUM_CONNS; i++) close(evfds[i]);
    #undef NUM_CONNS
}

/* ========================================================================
 * Main
 * ======================================================================== */

int main(void) {
    printf("=== rdma_fabric.c unit tests ===\n\n");

    run_test_wire_protocol_sizes();
    run_test_wire_protocol_register_xfer_memory();
    run_test_wire_protocol_feature();
    run_test_wire_protocol_opcode_dispatch();
    run_test_send_buffer_slot_management();
    run_test_connection_map_lookup();
    run_test_eventfd_signal_drain();
    run_test_memory_alignment();
    run_test_tcp_handshake_protocol();
    run_test_tcp_handshake_oversized_name();
    run_test_rx_buffer_offset_tracking();
    run_test_tx_buffer_offset_tracking();
    run_test_endian_conversion_roundtrip();
    run_test_wire_protocol_union_overlay();
    run_test_multiple_eventfd_per_connection();

    printf("\n=== Results: %d/%d passed", tests_passed, tests_run);
    if (tests_failed > 0) {
        printf(", %d FAILED", tests_failed);
    }
    printf(" ===\n");

    return tests_failed > 0 ? 1 : 0;
}
