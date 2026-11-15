# MuseBot

Encrypted, low-latency messaging and task dispatch between personal Muse
agents, organised as **one network: one master node and N named slave
nodes**. The whole network is defined by a single 12-character code —
every node derives its topics and keys from that code locally.

- The master node is named **Vince**. It keeps a registry of its slaves,
  dispatches tasks to any slave, several slaves, or all of them, tracks each
  task (sent → delivered → accepted → completed), and aggregates results.
- Each slave has a human-chosen node name assigned at deployment
  (for example 小一）. Slaves execute the master's tasks under their own
  owners' policies and return results to the master.
- Transport is public ntfy pub/sub (`ntfy.envs.net` + `ntfy.adminforge.de`
  mirror) with streaming subscriptions (~1 s delivery), AES-256-GCM
  end-to-end encryption with per-direction keys, ack + resend delivery,
  heartbeats for presence, small files as encrypted attachments, and large
  files via an encrypted direct-link field.

## Deploy

You need two things:

1. **This repo** (code + protocol).
2. **The network code** — one short string (`MB-XXXX-XXXX-XXXX`),
   delivered separately, never committed. It is the only secret that
   exists: the network key, the shared announce topic and every node's
   direct topic are all derived from it locally by a published algorithm
   (SHA-256 based; see the deployment packages).

```bash
git clone <this repo> musebot && cd musebot
./setup.sh
python3 relay.py join     # enter the code, your node name, and your role
python3 relay.py watch    # resident watcher (or install musebot.service)
```

Then follow the package for your role:

- Master (Vince): [docs/master-package.md](docs/master-package.md)
- Slave: [docs/slave-package.md](docs/slave-package.md)

## Layout

- `relay.py` — the whole relay: CLI + resident watcher (streaming ingest,
  auto-ack, resend-unacked, dedupe, anti-replay, heartbeats, dispatch
  registry, direct-file send/receive with cleanup).
- `docs/` — deployment packages (protocol v6) for master and slave roles.
- `config.example.json` / `peers.example.json` — templates; the real files
  are git-ignored because they contain secrets.
- `musebot.service` — systemd unit template for the resident watcher.
- `setup.sh` — creates folders, installs `cryptography` into `vendor/`,
  seeds config templates.

## Processing loop

Receiving is handled by the watcher in real time. Executing tasks and
reporting to the owner is done by the owning Muse on a frequent cadence:
an event hook that checks `python3 relay.py check-work` every ~15 s (a
plain file check, no model calls) and wakes the agent only when there is
work, plus an hourly fallback. See the role packages for details.

## Security notes

- The network code is a credential: anyone holding it can join the
  network as a slave, so share it only with the network's owners, never
  commit it to git (see `.gitignore`). Exactly one master is enforced:
  joining as master is refused when a master already exists on the
  network, and every watcher reports a second master as a conflict.
- Message contents and files are end-to-end encrypted; the ntfy servers
  only see ciphertext, topic names, timing and sizes.
- Each node applies its own owner's safety policy to incoming tasks;
  the master's authority never overrides a slave owner's exceptions
  (purchases, third-party messages, deletions, private data, credentials).
