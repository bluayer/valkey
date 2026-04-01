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

### 3D. Cross-Compatibility Test

Verify ibverbs client can talk to libfabric server (wire protocol unchanged):

```bash
# Server: libfabric
./valkey-server-fabric --loadmodule ./valkey-rdma-fabric.so \
  --port 0 --rdma-port 6379 --bind $SERVER_IP --protected-mode no

# Client: standard valkey-cli (uses libvalkey's ibverbs-based rdma.c)
./src/valkey-cli -u rdma://$SERVER_IP:6379 PING
```

---

## 4. Performance Tests

### 4A. Benchmark Script

```bash
#!/bin/bash
# perf_test.sh - Run on client node
SERVER_IP=$1
BACKEND=$2  # "fabric" or "verbs"

echo "=== Valkey RDMA Performance Test: $BACKEND ==="

for CLIENTS in 1 10 50 100; do
  for PAYLOAD in 64 256 1024 4096; do
    echo "--- clients=$CLIENTS payload=${PAYLOAD}B ---"
    ./src/valkey-benchmark -u rdma://$SERVER_IP:6379 \
      -t set,get -n 500000 -c $CLIENTS -d $PAYLOAD \
      --csv 2>/dev/null | grep -E "SET|GET"
  done
done
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

- **EFA `efa` provider vs `verbs` provider**: On EFA instances, libfabric has both
  an `efa` provider (SRD protocol) and a `verbs` provider (ibverbs compat).
  Our `rdma_fabric.c` should work with the `verbs` provider for wire-protocol
  compatibility. Set `FI_PROVIDER=verbs` if needed:
  ```bash
  export FI_PROVIDER=verbs
  ```
- **If `efa` provider is preferred**: The SRD protocol may require adjustments
  to the MR registration flags since EFA has different MR mode requirements.
  Test with `verbs` provider first.
- The client-side (`deps/libvalkey/src/rdma.c`) still uses ibverbs directly —
  this is out of scope and unchanged.
