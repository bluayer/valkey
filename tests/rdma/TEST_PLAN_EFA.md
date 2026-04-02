# Valkey RDMA libfabric Backend - EC2 EFA Test Plan

## Overview

This plan covers functional and performance testing of the libfabric RDMA backend
(`rdma_fabric.c`) on AWS EC2 using EFA (Elastic Fabric Adapter).

EFA natively uses libfabric with the `efa` provider, making it an ideal test target.

---

## 1. EC2 Infrastructure

### Instance Selection

| Instance Type  | vCPUs | RAM    | On-Demand   | Spot (~65% off) |
|---------------|-------|--------|-------------|-----------------|
| c5n.9xlarge   | 36    | 96 GB  | ~$1.94/hr   | ~$0.60/hr       |
| c6in.8xlarge  | 32    | 64 GB  | ~$1.81/hr   | ~$0.55/hr       |

**Recommendation**: 2x `c5n.9xlarge` spot in us-east-1 — **~$1.20/hr total**

### Requirements

- **Placement Group**: `cluster` strategy (mandatory for EFA)
- **Same AZ**: Both instances in the same availability zone
- **Security Group**: Self-referencing all-traffic rule (EFA uses SRD, not TCP/UDP)
- **EFA-enabled ENI**: Must be specified at launch time

### Launch Script

```bash
# 1. Create placement group
aws ec2 create-placement-group \
  --group-name valkey-efa-test \
  --strategy cluster

# 2. Create security group with self-referencing rule
SG_ID=$(aws ec2 create-security-group \
  --group-name valkey-efa-sg \
  --description "Valkey EFA RDMA testing" \
  --query 'GroupId' --output text)

aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID \
  --protocol -1 \
  --source-group $SG_ID

# Allow SSH
aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp --port 22 \
  --cidr 0.0.0.0/0

# 3. Launch 2 spot instances with EFA
aws ec2 run-instances \
  --instance-type c5n.9xlarge \
  --count 2 \
  --image-id ami-0c02fb55956c7d316 \
  --key-name <YOUR_KEY> \
  --placement "GroupName=valkey-efa-test" \
  --network-interfaces "DeviceIndex=0,InterfaceType=efa,Groups=$SG_ID,SubnetId=<YOUR_SUBNET>" \
  --instance-market-options '{"MarketType":"spot"}' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=valkey-efa-test}]'
```

---

## 2. Instance Setup (both nodes)

```bash
# EFA driver & libfabric installation
curl -O https://efa-installer.amazonaws.com/aws-efa-installer-latest.tar.gz
tar xf aws-efa-installer-latest.tar.gz
cd aws-efa-installer
sudo ./efa_installer.sh -y

# Verify EFA
fi_info -p efa         # Should list efa provider
fi_info -p verbs       # Should list verbs provider (for ibverbs comparison)

# Check provider capabilities (MR key size, modes, etc.)
cd valkey/tests/rdma
gcc -o test_mr_key_size test_mr_key_size.c -lfabric \
  -I/opt/amazon/efa/include -L/opt/amazon/efa/lib64
./test_mr_key_size efa

# Build dependencies
sudo yum install -y gcc make pkgconfig  # AL2023
# or: sudo apt install -y gcc make pkg-config  # Ubuntu

# Clone and build Valkey
git clone https://github.com/bluayer/valkey.git
cd valkey
git checkout claude/ibverbs-to-libfabric-X8oHG

# Set PKG_CONFIG_PATH (EFA installs to /opt/amazon/efa)
export PKG_CONFIG_PATH=/opt/amazon/efa/lib64/pkgconfig:$PKG_CONFIG_PATH
export LD_LIBRARY_PATH=/opt/amazon/efa/lib64:$LD_LIBRARY_PATH
```

---

## 3. Functional Tests

### 3A. Build Both Backends

```bash
# Build libfabric backend
make clean && make BUILD_RDMA=module RDMA_PROVIDER=fabric -j$(nproc)
cp src/valkey-rdma.so valkey-rdma-fabric.so
cp src/valkey-server valkey-server-fabric

# Build ibverbs backend (baseline)
make clean && make BUILD_RDMA=module -j$(nproc)
cp src/valkey-rdma.so valkey-rdma-verbs.so
cp src/valkey-server valkey-server-verbs
```

### 3B. Basic Connectivity (on Server node)

```bash
SERVER_IP=<private IP of server instance>

# Test 1: libfabric backend
./valkey-server-fabric \
  --loadmodule ./valkey-rdma-fabric.so \
  --port 0 --rdma-port 6379 \
  --bind $SERVER_IP --protected-mode no

# From client node:
./src/valkey-cli -u rdma://$SERVER_IP:6379 PING
./src/valkey-cli -u rdma://$SERVER_IP:6379 SET testkey testvalue
./src/valkey-cli -u rdma://$SERVER_IP:6379 GET testkey
```

### 3C. Existing RDMA Test Suite

```bash
# Run the built-in rdma test (tests/rdma/)
cd tests/rdma && make
python3 run.py
```

### 3D. Cross-Compatibility Note

**Important**: The libfabric backend uses TCP handshake for address exchange,
while the ibverbs backend uses RDMA CM (`rdma_connect`/`rdma_accept`).
These are incompatible connection protocols, so:

- **fabric server + ibverbs client = DOES NOT WORK**
- **ibverbs server + fabric client = DOES NOT WORK**

Both server and client must use the same backend. Since `valkey-cli` and
`valkey-benchmark` use `deps/libvalkey/src/rdma.c` (ibverbs), they cannot
connect to a fabric-backend server directly.

**For testing, use TCP port as a workaround**:
```bash
# Server: libfabric backend, but also enable TCP port for CLI access
./valkey-server-fabric --loadmodule ./valkey-rdma-fabric.so \
  --port 6380 --rdma-port 6379 --bind $SERVER_IP --protected-mode no

# Client: connect via TCP for admin/testing
./src/valkey-cli -h $SERVER_IP -p 6380 PING
```

**For RDMA-to-RDMA testing**, use the fabric test client:
```bash
# Build the fabric test client (on client node)
cd tests/rdma
gcc -o rdma-test-fabric rdma-test-fabric.c -lfabric -lpthread \
  -I/opt/amazon/efa/include -L/opt/amazon/efa/lib64

# Run against fabric server (PING, SET/GET, BGSAVE tests)
./rdma-test-fabric -h $SERVER_IP -p 6379

# Multi-threaded test
./rdma-test-fabric -h $SERVER_IP -p 6379 -t 4
```

---

## 4. Performance Tests

### 4A. Benchmark Script

**Note**: `valkey-benchmark` currently uses ibverbs RDMA, so direct RDMA
benchmarking of the fabric backend is not yet possible. Use TCP for now:

```bash
#!/bin/bash
# perf_test.sh - Run on client node (TCP mode for both backends)
SERVER_IP=$1
PORT=$2  # TCP port (e.g., 6380)

echo "=== Valkey Performance Test (TCP) ==="

for CLIENTS in 1 10 50 100; do
  for PAYLOAD in 64 256 1024 4096; do
    echo "--- clients=$CLIENTS payload=${PAYLOAD}B ---"
    ./src/valkey-benchmark -h $SERVER_IP -p $PORT \
      -t set,get -n 500000 -c $CLIENTS -d $PAYLOAD \
      --csv 2>/dev/null | grep -E "SET|GET"
  done
done
```

**For true RDMA benchmarking** (ibverbs backend only, as baseline):
```bash
./src/valkey-benchmark -u rdma://$SERVER_IP:6379 \
  -t set,get -n 500000 -c 50 -d 256 --csv
```

### 4B. Test Matrix

| Test                      | Metric           | Pass Criteria                          |
|--------------------------|------------------|----------------------------------------|
| SET 64B, 1 client        | ops/sec, p99 lat | fabric within 10% of verbs             |
| SET 4KB, 50 clients      | ops/sec, p99 lat | fabric within 10% of verbs             |
| GET 64B, 100 clients     | ops/sec, p99 lat | fabric within 10% of verbs             |
| GET 4KB, 100 clients     | throughput MB/s  | fabric within 10% of verbs             |
| Long-running (10min)      | stability        | No crashes, no memory leaks            |
| Reconnection              | connectivity     | Client reconnects after server restart |

### 4C. Comparison Procedure

```bash
# 1. Run server with ibverbs backend, benchmark, save results
./valkey-server-verbs --loadmodule ./valkey-rdma-verbs.so \
  --port 0 --rdma-port 6379 --bind $SERVER_IP --protected-mode no &
bash perf_test.sh $SERVER_IP verbs > results_verbs.csv
kill %1

# 2. Run server with libfabric backend, benchmark, save results
./valkey-server-fabric --loadmodule ./valkey-rdma-fabric.so \
  --port 0 --rdma-port 6379 --bind $SERVER_IP --protected-mode no &
bash perf_test.sh $SERVER_IP fabric > results_fabric.csv
kill %1

# 3. Compare
diff results_verbs.csv results_fabric.csv
# or use a script to compute % differences
```

---

## 5. Stability Tests

```bash
# Long-running test (10 minutes, mixed workload)
./src/valkey-benchmark -u rdma://$SERVER_IP:6379 \
  -t set,get,incr,lpush,rpush,sadd -n 10000000 -c 50 -d 256

# Memory leak check (compare RSS before/after)
ps -o rss -p $(pgrep valkey-server) # before
# ... run benchmark ...
ps -o rss -p $(pgrep valkey-server) # after
```

---

## 6. Cost Estimate

| Item                     | Duration | Cost        |
|--------------------------|----------|-------------|
| 2x c5n.9xlarge spot     | 3 hours  | ~$3.60      |
| EBS (gp3 50GB x2)       | 3 hours  | ~$0.02      |
| Data transfer (intra-AZ) | -        | $0          |
| **Total**                | **3 hours** | **~$3.62** |

---

## 7. Cleanup

```bash
# Terminate instances
aws ec2 terminate-instances --instance-ids <id1> <id2>

# Delete placement group (after instances terminate)
aws ec2 delete-placement-group --group-name valkey-efa-test

# Delete security group
aws ec2 delete-security-group --group-id $SG_ID
```

---

## Important Notes

- **Architecture**: `rdma_fabric.c` uses native **FI_EP_RDM** (reliable datagram),
  not FI_EP_MSG. This is the only endpoint type EFA supports natively.
  - **Shared endpoint**: One RDM endpoint for all connections, peers identified by `fi_addr_t`
  - **TCP handshake**: Replaces RDMA CM. The server listens on a TCP socket; clients
    connect via TCP, exchange `fi_getname` addresses, then communicate via RDMA.
  - **Address Vector (AV)**: `fi_av_insert()` registers peers after TCP handshake
  - **Global CQ**: `fi_cq_readfrom()` returns source address for demuxing
  - **eventfd per connection**: Bridges shared CQ to Valkey's per-fd ae event loop
- **EFA provider**: Uses the `efa` provider (SRD protocol) with FI_EP_RDM.
  Set `FI_PROVIDER=efa` to force EFA provider (usually auto-detected):
  ```bash
  export FI_PROVIDER=efa
  ```
- **EFA-specific capabilities and limitations**:
  - `FI_MR_ENDPOINT`: EFA requires MR bound to endpoint. Handled automatically.
  - `FI_CONTEXT2`: EFA requires 64-byte operation context. The code uses `RdmaOpCtx`
    wrapper struct (fi_context2 + user_data pointer) for all operations.
  - `FI_RX_CQ_DATA`: EFA requires this mode for receiving immediate data. Set in hints.
  - `FI_RMA_EVENT`: **NOT supported** by EFA. Not needed — our data path uses
    `fi_writemsg` + `FI_REMOTE_CQ_DATA` which generates receive completions
    through the posted recv buffer mechanism, not through RMA target events.
  - `FI_WAIT_FD`: Supported by EFA for CQ notification **when SHM is disabled**.
    Cross-node RDMA disables SHM automatically. If using loopback testing on a
    single EFA instance, set `FI_EFA_USE_SHM=0` to avoid FI_WAIT_FD failures:
    ```bash
    export FI_EFA_USE_SHM=0
    ```
  - **MR key size**: EFA uses 8-byte MR keys. The fabric wire protocol extends
    `ValkeyRdmaMemory.key` to `uint64_t` (the ibverbs backend uses `uint32_t`).
    This is safe because fabric and ibverbs backends cannot interoperate anyway.
- **Wire protocol**: The 32-byte ValkeyRdmaCmd union size is preserved. The fabric
  backend uses a modified `ValkeyRdmaMemory` layout with 64-bit key field:
  ```
  ibverbs: opcode(2) + rsvd(14) + addr(8) + length(4) + key(4)  = 32
  fabric:  opcode(2) + rsvd(6)  + addr(8) + key(8) + length(4) + rsvd2(4) = 32
  ```
  RDMA writes use `fi_writemsg` with `FI_REMOTE_CQ_DATA` (equivalent to ibverbs
  `IBV_WR_RDMA_WRITE_WITH_IMM`).
- **Client-side note**: The client (`deps/libvalkey/src/rdma.c`) still uses ibverbs
  with rdma_cm. It uses a different connection protocol (RDMA CM) than the fabric
  backend (TCP handshake), so **they are NOT cross-compatible**. Both sides must
  use the same backend. A fabric-aware libvalkey client is a future task.
- **Benchmarking limitation**: `valkey-benchmark` uses ibverbs RDMA, so it cannot
  benchmark the fabric backend over RDMA directly. Use TCP port for benchmark
  comparisons, or develop a fabric-aware benchmark client.
