# Blockchain-based Log Integrity System (Defense-Grade)

**Objective**: Ensure tamper‑proof logging with verifiable integrity, access control, and full audit trails using a private permissioned blockchain (Hyperledger Fabric).

---

## 0) High‑Level Overview

### Why Fabric?
- **Permissioned**: X.509 identities and MSPs for strict access control.
- **Immutable**: Append‑only ledger; any change is detectable.
- **Private Data**: Optional private data collections for sensitive payloads.
- **Pluggable Governance**: Endorsement policies, channels, and CA-issued attributes.

### Core Idea
- **Off‑chain**: Store raw logs in secured storage (e.g., MinIO/S3, NAS, or WORM).
- **On‑chain**: Store only cryptographic digests (SHA‑256) + metadata (source, timestamp, URI, signer).
- **Verify**: Re-hash raw log and compare with on‑chain hash.
- **Access Control**: Attribute‑Based Access Control (ABAC) enforced in chaincode using certificate attributes.

### Minimal Architecture (Dev)
```
[Log Sources] -> [Collector/Agent] -> [Ingest API] -> [Fabric Client SDK]
                                                 |-> [MinIO/S3 Off-chain]
                                       [Orderer/Peers/CouchDB]
                                                  ^
                                                [CA]
```

---

## 1) Threat Model (Abbreviated)
- **A1**: Insider tampers with stored logs → mitigated by on‑chain hashes + signatures.
- **A2**: Network spoofing → TLS mutual auth; signed transactions; syslog/TLS if used.
- **A3**: Key compromise → HSM or soft-HSM; short‑lived certs; rotation.
- **A4**: Data exfiltration → on‑chain stores no plaintext logs; off‑chain encryption at rest + RBAC.

---

## 2) Prerequisites
- Linux host (Ubuntu 22.04+ or RHEL 9+ recommended), 4+ vCPU, 8 GB RAM.
- Docker & Docker Compose.
- Node.js 18+ (for API client/chaincode sample) or Go 1.20+ (if using Go chaincode).
- cURL, jq, make, OpenSSL.
- Hyperledger Fabric binaries & samples (local dev).

> **Tip**: Use Fabric test network for quick bring‑up; move to Kubernetes for prod.

---

## 3) Bring up a Local Fabric Network (Dev/Test)

> Uses Fabric test network (2 orgs, RAFT orderer, CouchDB, 1 channel `logs`)

```bash
# 3.1 Get Fabric samples & binaries (if not already)
mkdir -p ~/fabric && cd ~/fabric
# Follow official script to pull binaries; place binaries in ~/fabric/bin and add to PATH
export PATH=~/fabric/bin:$PATH

# 3.2 Clone samples (if not present)
git clone https://github.com/hyperledger/fabric-samples.git
cd fabric-samples/test-network

# 3.3 Bring up network with CAs and CouchDB
./network.sh up createChannel -c logs -ca -s couchdb

# 3.4 (Optional) Create a separate channel for higher secrecy (e.g., ops)
# ./network.sh createChannel -c ops
```

Result: two orgs (`Org1MSP`, `Org2MSP`), one channel `logs`, identities under `organizations/`.

---

## 4) Chaincode (Smart Contract) Design

### Data Model
```ts
// TypeScript interface (conceptual)
interface LogRecord {
  id: string;              // ULID/UUID for this log object (or deterministic key)
  sourceId: string;        // system/app/sensor identifier
  ts: string;              // ISO 8601 timestamp from collector
  hash: string;            // sha256 hex digest of raw payload
  uri?: string;            // off-chain location (s3://bucket/key or file:///...)
  signer?: string;         // subject / cert fingerprint of submitter
  meta?: Record<string, string>; // any additional labels
}
```

### Access Roles (via cert attributes)
- `role=admin` → can register sources, manage ACLs, rotate policies.
- `role=writer` → can append log entries for authorized `sourceId`s.
- `role=auditor` → can read & verify all (or subset per policy).

Attributes embedded in certs by the CA (ABAC).

### Endorsement Policy Examples
- **Simple**: `OR('Org1MSP.peer','Org2MSP.peer')` for general operations.
- **Sensitive**: `AND('Org1MSP.peer','Org2MSP.peer')` for ACL changes.

---

## 5) Implement Chaincode (TypeScript Example)

**Structure**: `fabric-samples/chaincode/logcc-typescript/`

**package.json** (excerpt)
```json
{
  "name": "logcc",
  "version": "1.0.0",
  "main": "dist/index.js",
  "scripts": {
    "build": "tsc",
    "start": "node dist/index.js"
  },
  "dependencies": {
    "fabric-contract-api": "^2.6.0",
    "fabric-shim": "^2.6.0"
  },
  "devDependencies": {
    "typescript": "^5.6.0"
  }
}
```

**tsconfig.json** (minimal)
```json
{
  "compilerOptions": { "module": "commonjs", "target": "es2019", "outDir": "dist", "declaration": true },
  "include": ["src/**/*.ts"]
}
```

**src/index.ts** (core logic; trimmed for brevity but runnable pattern)
```ts
import { Context, Contract } from 'fabric-contract-api';

class LogContract extends Contract {
  async InitLedger(ctx: Context) {
    return 'OK';
  }

  private async requireAttr(ctx: Context, key: string, expected?: string) {
    const cid: any = ctx.clientIdentity;
    const val = cid.getAttributeValue(key);
    if (!val) throw new Error(`Missing attribute ${key}`);
    if (expected && val !== expected) throw new Error(`Attr ${key} != ${expected}`);
    return val as string;
  }

  private async put(ctx: Context, key: string, value: unknown) {
    await ctx.stub.putState(key, Buffer.from(JSON.stringify(value)));
  }

  private async get(ctx: Context, key: string) {
    const b = await ctx.stub.getState(key);
    if (!b || b.length === 0) throw new Error('Not found');
    return JSON.parse(b.toString());
  }

  /** Register a log source with optional write ACL list */
  async RegisterSource(ctx: Context, sourceId: string, description: string, writersCsv: string) {
    await this.requireAttr(ctx, 'role', 'admin');
    const exists = await ctx.stub.getState(`SRC_${sourceId}`);
    if (exists && exists.length) throw new Error('Source exists');
    const writers = (writersCsv || '').split(',').map(s => s.trim()).filter(Boolean);
    await this.put(ctx, `SRC_${sourceId}`, { sourceId, description, writers });
    return 'OK';
  }

  /** Append a log record */
  async AppendLog(ctx: Context, id: string, sourceId: string, ts: string, hash: string, uri: string, metaJson: string) {
    // ABAC: require writer
    const role = await this.requireAttr(ctx, 'role');
    if (role !== 'writer' && role !== 'admin') throw new Error('Not writer');

    // Check source and ACL
    const srcB = await ctx.stub.getState(`SRC_${sourceId}`);
    if (!srcB || srcB.length === 0) throw new Error('Unknown source');
    const src = JSON.parse(srcB.toString());

    // Optional: check that invoker's cert subject is in writers
    const cid: any = ctx.clientIdentity;
    const invoker = cid.getID(); // X.509 subject/issuer hash
    if (src.writers && src.writers.length && !src.writers.includes(invoker)) {
      throw new Error('Invoker not in writers ACL');
    }

    // Enforce immutability of id
    const key = `LOG_${id}`;
    const old = await ctx.stub.getState(key);
    if (old && old.length) throw new Error('Duplicate id');

    const rec = { id, sourceId, ts, hash: hash.toLowerCase(), uri, signer: invoker, meta: JSON.parse(metaJson || '{}') };
    await this.put(ctx, key, rec);

    // Index by sourceId and by hash for queries
    await this.put(ctx, `IDX_SRC_${sourceId}_${id}`, { id });
    await this.put(ctx, `IDX_HASH_${hash.toLowerCase()}_${id}`, { id });

    return id;
  }

  /** Get a log record by id */
  async GetLog(ctx: Context, id: string) {
    return await this.get(ctx, `LOG_${id}`);
  }

  /** Verify recomputed hash vs on-chain */
  async VerifyHash(ctx: Context, id: string, recomputedHash: string) {
    const rec = await this.get(ctx, `LOG_${id}`);
    const ok = rec.hash === recomputedHash.toLowerCase();
    return { id, ok, expected: rec.hash, got: recomputedHash.toLowerCase() };
  }

  /** Query by hash */
  async FindByHash(ctx: Context, hash: string) {
    // Simple key-scan via partial composite keys (or use rich queries with CouchDB)
    const iterator = await ctx.stub.getStateByRange(`IDX_HASH_${hash.toLowerCase()}_`, `IDX_HASH_${hash.toLowerCase()}_~`);
    const ids: string[] = [];
    for await (const kv of iterator as any) {
      const v = JSON.parse(kv.value.toString());
      ids.push(v.id);
    }
    return ids;
  }

  /** History / Audit trail of a log record */
  async History(ctx: Context, id: string) {
    const key = `LOG_${id}`;
    const iterator = await ctx.stub.getHistoryForKey(key);
    const items: any[] = [];
    for await (const r of iterator as any) {
      items.push({ txId: r.txId, timestamp: r.timestamp, isDelete: r.isDelete, value: r.value.toString() });
    }
    return items;
  }
}

export const contracts: any[] = [new LogContract()];
```

> **Notes**
> - For production, use **composite keys** (e.g., `ctx.stub.createCompositeKey('HASH', [hash, id])`) and **CouchDB rich queries** with indexes.
> - Consider **private data collection** for source writer lists or sensitive metadata.

---

## 6) Deploy Chaincode

From `fabric-samples/test-network`:
```bash
# 6.1 Package & deploy (Fabric sample helper)
./network.sh deployCC -c logs -ccn logcc -ccp ../chaincode/logcc-typescript -ccl typescript

# 6.2 Test with peer CLI (Org1)
export PATH=~/fabric/bin:$PATH
. ./scripts/envVar.sh
setGlobals 1

peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
  --tls --cafile "$ORDERER_CA" -C logs -n logcc \
  --isInit -c '{"Args":["InitLedger"]}'

# Query (should return OK or empty state depending on implementation)
peer chaincode query -C logs -n logcc -c '{"Args":["GetLog","nonexistent"]}' || true
```

---

## 7) Issue Identities with Roles (CA / ABAC)

Use Fabric CA to enroll users with attributes:
```bash
# Admin creates a writer with role attribute
fabric-ca-client register --id.name writer1 --id.secret pw --id.type client \
  --id.attrs 'role=writer:ecert' -u https://localhost:7054 --mspdir organizations/fabric-ca/org1

# Enroll to get cert embedding role=writer
fabric-ca-client enroll -u https://writer1:pw@localhost:7054 \
  -M organizations/peerOrganizations/org1.example.com/users/writer1@org1.example.com/msp \
  --enrollment.attrs role
```

> Embed additional attributes such as `clearance=secret`, `unit=navy` to support fine-grained ABAC in chaincode.

---

## 8) Off‑Chain Storage (MinIO/S3) Option

- Deploy MinIO (dev) or point to S3 (prod).
- Collector uploads raw log file → receives `s3://bucket/key` URI.
- API computes **SHA‑256** of raw bytes; submits `AppendLog(id, sourceId, ts, hash, uri, metaJson)`.

---

## 9) Ingest API (Node.js + Fabric SDK)

**Folder**: `apps/ingest-api/`

**package.json**
```json
{
  "name": "ingest-api",
  "version": "1.0.0",
  "type": "module",
  "scripts": { "start": "node server.js" },
  "dependencies": {
    "express": "^4.19.0",
    "multer": "^1.4.5",
    "aws-sdk": "^2.1580.0",
    "fabric-network": "^2.2.19",
    "ulid": "^2.3.0",
    "crypto": "^1.0.1"
  }
}
```

**server.js** (simplified)
```js
import express from 'express';
import crypto from 'crypto';
import multer from 'multer';
import fs from 'fs';
import { ulid } from 'ulid';
import { Gateway, Wallets } from 'fabric-network';

const app = express();
app.use(express.json());
const upload = multer({ dest: '/tmp' });

async function getContract(identityLabel = 'writer1') {
  const ccp = JSON.parse(fs.readFileSync('./ccp-org1.json'));
  const wallet = await Wallets.newFileSystemWallet('./wallet');
  const gateway = new Gateway();
  await gateway.connect(ccp, { wallet, identity: identityLabel, discovery: { enabled: true, asLocalhost: true } });
  const network = await gateway.getNetwork('logs');
  return { contract: network.getContract('logcc'), gateway };
}

app.post('/ingest', upload.single('log'), async (req, res) => {
  try {
    const { sourceId, ts, meta } = req.body;
    const filePath = req.file?.path;
    const data = fs.readFileSync(filePath);
    const hash = crypto.createHash('sha256').update(data).digest('hex');

    // TODO: upload data to S3/MinIO and get URI
    const uri = `file://${filePath}`;
    const id = ulid();

    const { contract, gateway } = await getContract();
    const metaJson = JSON.stringify(meta ? JSON.parse(meta) : {});
    await contract.submitTransaction('AppendLog', id, sourceId, ts, hash, uri, metaJson);
    await gateway.disconnect();

    res.json({ id, sourceId, ts, hash, uri });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/verify/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { path, recompute } = req.query;
    const data = fs.readFileSync(path);
    const hash = crypto.createHash('sha256').update(data).digest('hex');

    const { contract, gateway } = await getContract('auditor1');
    const result = await contract.evaluateTransaction('VerifyHash', id, hash);
    await gateway.disconnect();

    res.json(JSON.parse(result.toString()));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.listen(8080, () => console.log('Ingest API listening on :8080'));
```

> Place `ccp-org1.json` (connection profile) and identities (`wallet/`) from the network artifacts.

---

## 10) Register Log Sources & Append Logs (Flow)

1. **Admin** calls `RegisterSource('sensor-alpha', 'Edge radar', 'x509-subject1,x509-subject2')`.
2. **Writer** (agent) sends a file/line batch to `/ingest`.
3. API computes SHA‑256, uploads to storage, submits `AppendLog(...)` to chaincode.
4. **Auditor** retrieves `GetLog(id)` and `History(id)`; independently re-hashes raw bytes and calls `VerifyHash`.

---

## 11) Integrating with System Logs

### Option A: Fluent Bit Agent (recommended)
- Tail files (`/var/log/...`), buffer/ship to HTTP or to a local collector.
- Exec plugin can compute SHA‑256 per record/file segment (or compute in collector).

**fluent-bit.conf** (sketch)
```ini
[INPUT]
    Name tail
    Path /var/log/syslog
    Refresh_Interval 5

[FILTER]
    Name   lua
    Match  *
    script hash.lua
    call   addhash

[OUTPUT]
    Name  http
    Match *
    Host  ingest.local
    Port  8080
    URI   /ingest
    Format json
```

**hash.lua** (example)
```lua
function addhash(tag, ts, record)
  local sha256 = require('crypto').sha256 -- or external binding
  if record["message"] then
    record["hash"] = sha256(record["message"]) -- else compute in server
  end
  return 1, ts, record
end
```

### Option B: rsyslog → program pipe

**/etc/rsyslog.d/90-blockchain.conf**
```conf
$template JSONfmt,"{\"ts\":\"%timereported:::date-rfc3339\",\"host\":\"%HOSTNAME%\",\"msg\":\"%msg%\"}\n"
*.* action(type="omprog" binary="/usr/local/bin/ship-to-ingest.sh" template="JSONfmt")
```

**/usr/local/bin/ship-to-ingest.sh** (reads JSON lines from stdin and POSTs)
```bash
#!/usr/bin/env bash
set -euo pipefail
while IFS= read -r line; do
  ts=$(echo "$line" | jq -r .ts)
  msg=$(echo "$line" | jq -r .msg)
  hash=$(printf "%s" "$msg" | sha256sum | awk '{print $1}')
  curl -sS -X POST http://ingest.local:8080/ingest \
    -F sourceId="syslog-host1" \
    -F ts="$ts" \
    -F meta="{\"host\":\"$(hostname)\"}" \
    -F log=@<(echo "$msg" | sed 's/$/\n/') >/dev/null || true

done
```

> For defense networks, prefer **mutual TLS** between agent and API.

---

## 12) Verifying Integrity (Auditor Workflow)

1. Fetch raw payload from URI (S3/MinIO or file).
2. Compute SHA‑256 → `H`.
3. Call chaincode `VerifyHash(id, H)` → must return `ok=true`.
4. Optionally compare with on‑chain `History(id)` to ensure no deletes/overwrites.

**CLI example**
```bash
peer chaincode query -C logs -n logcc -c '{"Args":["GetLog","01J4...ULID"]}' | jq
peer chaincode query -C logs -n logcc -c '{"Args":["History","01J4...ULID"]}' | jq
```

---

## 13) Audit Trail & Forensics
- Fabric stores **txId**, **creator identity**, **timestamp**, and **RW sets** per transaction.
- `History(id)` exposes all changes; deletions show `isDelete=true`.
- Keep **channel block files** for legal hold; export to secure archive.

---

## 14) Security Hardening (Prod)
- **mTLS everywhere**: peers, orderers, SDK→gateway, agents→API.
- **HSM**: Store client private keys in HSM or PKCS#11 provider.
- **CA policies**: Short‑lived certs, CRL distribution, attribute issuance approvals.
- **Channels/Collections**: Split sensitive sources into separate channels/private collections.
- **Endorsement**: Use `AND` for high‑impact functions (ACL updates), `OR` elsewhere.
- **Block cutting**: Tune `BatchTimeout`/`BatchSize` for throughput/latency.
- **CouchDB**: Create JSON indexes for common queries (e.g., by `sourceId`, `hash`).
- **Logging**: Enable Fabric audit logs; forward to SIEM.
- **Zero trust ingress**: WAF + authz for API; IP allowlists.

---

## 15) Performance & Scalability
- Separate ingest into **micro-batches** (e.g., one chain tx per file or per N lines) to reduce TPS load.
- Use **asynchronous queue** (Kafka/RabbitMQ/NATS) between collector and API to smooth bursts.
- Horizontal scale of **peers** and **API** behind mTLS ingress.

---

## 16) Testing Strategy
- **Unit tests**: Chaincode functions (happy path + RBAC denials + duplicates).
- **Integration tests**: Start test network in CI; run jest/mocha against gateway.
- **Property tests**: Random log blobs → expect deterministic SHA‑256.
- **Negative tests**: Tampered payload should fail `VerifyHash`.

---

## 17) Kubernetes (Prod Sketch)
- Deploy orderers/peers with stable storage (NVMe SSD), enable node affinity/anti‑affinity.
- Use **Helm** charts or Fabric Operator; mount MSP secrets from KMS/CSI vault.
- Sidecar **Prometheus exporters**; **Grafana** dashboards.
- MinIO/S3 with object‑lock (WORM) if policy requires immutability.

---

## 18) Operations & DR
- Periodic **snapshots** of channel blocks and CouchDB state; store offsite.
- Maintain **genesis block**, MSP roots, CA DB backups.
- **Rebuild** peers from block archives when needed.

---

## 19) Compliance Notes (Defense Context)
- Map controls to **NIST 800-53** (AU‑2/3/6, SC‑12, CM‑6), **ISO 27001 A.12/A.18**.
- Maintain **chain of custody** docs for logs and keys.

---

## 20) Acceptance Checklist
- [ ] Can register a source with ACL.
- [ ] Can ingest log → on-chain hash + metadata recorded.
- [ ] Off-chain payload stored and retrievable.
- [ ] VerifyHash returns `ok=true` for genuine, `ok=false` for tampered.
- [ ] History shows immutable trail with identities.
- [ ] RBAC enforced (writer vs auditor vs admin).
- [ ] mTLS and CA attr issuance validated.

---

## 21) Quick Demo Commands (Happy Path)
```bash
# Admin (Org1) registers a source
peer chaincode invoke -C logs -n logcc -o localhost:7050 --tls --cafile "$ORDERER_CA" \
  -c '{"Args":["RegisterSource","sensor-alpha","Edge radar","x509::/C=US/.../CN=writer1@org1"]}'

# API ingests a file and prints returned id/hash
curl -F sourceId=sensor-alpha -F ts=$(date -Iseconds) -F meta='{"env":"dev"}' -F log=@/var/log/syslog \
  http://localhost:8080/ingest

# Auditor verifies
curl http://localhost:8080/verify/01J4ABCDEF?path=/tmp/<uploaded-file>
```

---

## 22) Enhancements (Next Iterations)
- **Signing**: Sign log digests with device private key; record signature on-chain.
- **Merkle trees**: Batch logs into trees; anchor the root hash to reduce on-chain load.
- **Anchoring to public chain**: Periodically anchor Fabric block hash to a public chain (for external notarization).
- **Time-stamping**: RFC 3161 TSA or chrony‑disciplined clocks for trustworthy `ts`.
- **Query API**: Auditor dashboard with filters by source/hash/time.

---

## 23) Troubleshooting Notes
- Chaincode failing with MVCC_READ_CONFLICT → retry with backoff.
- Discovery errors from SDK → check `asLocalhost` and core.yaml gossip settings.
- Attribute not visible → ensure `:ecert` flag when issuing attrs via Fabric CA.

---

### Deliverables Included Here
- End-to-end **step-by-step** for standing up Fabric,
- **Chaincode** (TypeScript) pattern for log integrity with ABAC,
- **Ingest API** scaffolding,
- **Agent** integration options,
- **Security** and **Ops** guidance,
- **Acceptance** checklist.

> You can copy these sections into your repo, scaffold the folders as indicated, and iterate.

