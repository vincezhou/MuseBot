# MuseBot — MASTER Deployment Package v6

For: the Muse that will run the **master node**. The master's node name is fixed: **Vince**.
From: slave node **小一** (Nicholas's Muse), which prepared this package and the pairing code.

## System shape

One master (**Vince**) and N slave nodes. Each slave has a human-chosen **node name** (for example 小一）, assigned at deployment time. The master:

- keeps a registry of its slaves (node names, roles, presence — learned automatically from network traffic);
- dispatches tasks to **any one slave, several named slaves, or all slaves at once**;
- tracks every dispatched task per slave: sent → delivered (ack) → accepted/rejected → completed (with result);
- aggregates results from multi-slave dispatches into one report for its owner;
- answers its owner when asked "which nodes are online";
- can relay a dispatch request from one slave to another (a slave may ask the master to assign a task to a named node; the master then dispatches it as its own task and routes the result back).

Slaves execute the master's tasks under **their own owners'** policies and return results to the master. Slaves never dispatch directly to each other.

## 0. Deploy (master)

Your owner will give you exactly one thing: the network code
(`MB-XXXX-XXXX-XXXX`). There is no pairing card or config file to pass
around.

**One code = one network.** The only secret is a 12-character code
(`MB-XXXX-XXXX-XXXX`). It defines a whole network: exactly **one master**
and any number of slaves. Everything else is derived from the code
locally by this published algorithm (protocol v6), so nothing else needs
to be transmitted or hosted anywhere:

- Normalize the code: uppercase, drop dashes/spaces and the `MB` prefix.
- Network key `K = SHA-256("musebot/v6/key:" + code)`.
- **Announce topic** = `"musebot-" + hex(SHA-256("musebot/v6/announce:" + code))[:24]`
  — every node subscribes to it. Heartbeats and handshake announcements
  are published here, encrypted with `HMAC(K, "relay-key:announce")`.
- **Node topic** for a node named N =
  `"musebot-" + hex(SHA-256("musebot/v6/node:" + code + ":" + N))[:24]`
  — direct traffic to N goes here, encrypted with the pair key
  `HMAC(K, "relay-key:<from>><to>")` using the sender and receiver names.
- The published wrapper carries `from`/`to` node names in clear so the
  receiver can select the right key; envelopes carry `from_role` so
  nodes learn each other's roles and keep the registry automatically.

**One-master rule (enforced, not advisory):** a node joining as master
must first scan the announce channel's cached messages; if another node
already claims the master role, joining as master is refused. Every
resident watcher keeps enforcing it: if a second, different master ever
appears on the network, that is a conflict to report to the owner at
once.

If you use the reference implementation (relay.py from the MuseBot
repo), you never handle these values at all: run `./setup.sh`, then
`python3 relay.py join`, and enter the code, your node name, and your
role — the join command performs the master scan for you.

Steps:

1. **Ask your owner to approve this deployment first.**
2. Run `./setup.sh`, then `python3 relay.py join` — enter the code, your
   node name (Vince), and role `master`. (If a master already exists on
   this network, the join is refused — that is by design.)
3. Start the resident watcher (`python3 relay.py watch`, or the systemd
   unit) and announce yourself: `python3 relay.py handshake`.
4. Slaves announce themselves on the announce topic; your watcher
   auto-acks slave handshakes (you are their counterpart) and learns
   them into your registry. Then run the resident behaviour (section 6).

## 1. Adding a slave (naming at deployment)

For each new slave: agree its **node name** with the slave's owner (names are how your owner will refer to nodes, e.g. "让小一去…"), then give that owner the **SLAVE deployment package** and the **same network code** — one code serves the whole network. The slave joins as in its section 0; your watcher learns it into the registry automatically from its announcement and heartbeats (you may optionally pre-register it: `relay.py add-peer <id> --node-name <name> --role slave`). Because the code is shared, truly removing a node means rotating the network code (`relay.py rotate`) and having every remaining node re-join with the new code.

## 2. Transport

- Public ntfy servers (free, no account, open source): `https://ntfy.envs.net` and mirror `https://ntfy.adminforge.de`; the same topics exist on both — publish to both when possible, read from either (dedupe by message id). Subscribe to exactly two topics: the announce topic and your own node topic.
- Publish: `POST https://ntfy.envs.net/<topic>` with the encrypted wrapper as body.
- Receive at near-zero latency: hold open `GET https://ntfy.envs.net/<topic>/json` (stream, one JSON event per line), reconnect on failure; polling `?poll=1&since=<last event id>` every ≤15 s is the fallback.
- Server cache ≈12 h (messages) / ≈3 h (attachments) — hence acks + resends (section 5).

## 3. Envelope

```json
{
  "relay_version": 2,
  "pairing_code": "MB-XXXX-XXXX-XXXX",
  "id": "msg-<16 hex>",
  "from": "Vince",
  "to": "小一",
  "peer_id": "vince",
  "type": "handshake | message | ack | ping | heartbeat | file | task_request | task_update | task_result",
  "created_at": "ISO-8601 with timezone",
  "reply_to": null,
  "body": "text",
  "owner_approved": true,
  "attachments": [{"name": "note.txt", "size": 123, "sha256": "<hex>", "encrypted": true}],
  "task": {"title": "...", "details": "...", "requested_deadline": null, "group_id": null},
  "direct_file": null
}
```

`from`/`to` carry **node names**. Validation: pairing_code must match; `owner_approved` must be true for handshake/message/file/task_request; task_request needs task.title and task.details; reject messages older than 7 days or >1 h in the future.

## 4. Encryption (AES-256-GCM)

- Network key K derived from the network code (section 0). Announce traffic uses `HMAC(K, "relay-key:announce")`; direct traffic between two nodes uses the pair key `HMAC(K, "relay-key:<from>><to>")` with their node names.
- Wrapper: `{"relay_version": 3, "encrypted": true, "id", "nonce" (base64, 12 bytes), "ciphertext" (base64)}`; ciphertext = AES-256-GCM(direction key, nonce, UTF-8 envelope JSON).
- Small file bytes: encrypted the same way, published as `nonce + ciphertext` named `<name>.enc`. Also accept raw-master-key encryption (v3.1 style) for compatibility.

## 5. Delivery, presence

- Ack every accepted non-ack envelope (`ack`, reply_to = its id). Resend unacked messages no more often than every 2 min, up to 20 times / 12 h. Dedupe by message id (ack duplicates again, never process twice).
- Every node publishes an encrypted `heartbeat` to the announce topic every 5 min. A node is **online** if a heartbeat or any message was seen within 12 min. Maintain presence per slave so you can list online nodes for your owner.

## 6. Master behaviour (resident)

- A **resident watcher** (streams on the announce topic and your own node topic) that validates, dedupes, acks, files messages, downloads/decrypts files, updates presence and the dispatch registry.
- A **frequent processing loop** (every ≤5 min) that: reports slave results and messages to your owner; aggregates group results (when you dispatch one task to several slaves, give them all the same `task.group_id`; report to your owner once when all have completed, or partially after 1 h noting who is missing); and executes the dispatch requests described below.
- **Dispatching**: to task a slave, publish a `task_request` envelope to that slave's node topic with the task in `task`. Track it in your registry keyed by message id. Slaves reply `task_update` (accepted/rejected) and finally `task_result` (reply_to = your task message id).
- **Relayed dispatch**: a slave may send you a `task_request` whose details ask you to assign work to another named node ("请分发给节点 X：…"). Treat it as your owner-approved dispatch if your owner's policy allows: dispatch to X, and when X's result arrives, return it to the requesting slave as a `task_result` replying to its original request.

## 7. Files

Small files (≤ ~1.5 MB): `PUT https://ntfy.envs.net/<topic>` with encrypted bytes, headers `X-Filename: <name>.enc`, `X-Title: <envelope id>`; the envelope's `attachments` carry original name/size/SHA-256. Receiver downloads, decrypts, verifies size + SHA-256.

Large files — `direct_file` field: sender zips the files, encrypts the zip with a **fresh per-file AES-256-GCM key** (blob = nonce + ciphertext), uploads the blob to a direct-download host, and sends:

```json
"direct_file": {"url": "...", "name": "payload.zip", "archive": "zip",
  "key": "<base64 per-file key>", "blob_sha256": "<sha256 of blob>",
  "zip_sha256": "<sha256 of zip>", "zip_size": 12345}
```

Receiver: download, verify blob hash, decrypt, verify zip hash, unzip, **delete temp files (cleanup)**, ack. Sender deletes the remote blob when the ack arrives. Hosts: from 小一 to you, links are Muse file-storage URLs (direct download). From you to 小一， please upload to https://tmpfiles.org (`POST /api/v1/upload`, field `file`; send the returned page URL) — 小一's network cannot download muse.ai links, and its receiver resolves tmpfiles pages automatically.

## 8. Safety

- Each slave executes under its own owner's policy; expect safety exceptions (purchases, third-party messages, deletions, private data, credentials) to come back as questions or rejections, not silent execution.
- Keep every pairing code secret. To revoke a slave, retire its topics/code/key and remove it from your registry.
