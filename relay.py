#!/usr/bin/env python3
"""MuseBot - encrypted master/slave relay between Muse agents. Protocol v6.

Design (protocol v6):
- One master node (fixed name: Vince) and N named slave nodes; this node's
  name/role are in config.json `self` (see relay_id / self block).
- peers.json is the address book: one entry per remote node with its own
  ntfy topics (plus mirror), pairing code and AES-256 master key.
  Direction keys are derived per peer via HMAC labels (n2p / p2n).
- Transport: public ntfy (primary + mirror). HTTP calls go through
  curl first (it survives the egress proxy where Python urllib
  intermittently fails with SSL WRONG_VERSION_NUMBER) and fall back
  to urllib. The resident watcher uses
  streaming subscriptions (~1s latency), auto-acks everything it ingests,
  resends unacknowledged outgoing messages, dedupes by message id and
  rejects replays older than 7 days.
- Every envelope and small file is AES-256-GCM encrypted before publish.
  Large files travel via a `direct_file` field: zip + fresh per-file key,
  uploaded to a direct link; the receiver verifies hashes, decrypts,
  unzips and cleans up; the sender deletes the blob once acked.
- The master dispatches tasks to any/several/all slaves and tracks each
  one in tasks/outgoing.json until every slave reports a result.
"""
import argparse, base64, hashlib, hmac as hmac_mod, json, os, random, re, secrets, shutil, socket, ssl, subprocess, sys, tempfile, threading, time, urllib.request, urllib.error, uuid, zipfile
from urllib.parse import urlparse
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE / "vendor"))
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:
    AESGCM = None

INBOX, OUTBOX, PROCESSED = BASE / "inbox", BASE / "outbox", BASE / "processed"
TO_PEER = BASE / "transport" / "to_peer"
FROM_PEER = BASE / "transport" / "from_peer"
FILES_TO_PEER = BASE / "transport" / "files_to_peer"
FILES_FROM_PEER = BASE / "transport" / "files_from_peer"
FILES_RECEIVED = BASE / "files" / "received"
FILES_SENT = BASE / "files" / "sent"
TASKS_IN = BASE / "tasks" / "incoming"
PENDING = BASE / "transport" / "pending"
STATE_F = BASE / "transport" / "state.json"
PRESENCE_F = BASE / "presence.json"
PEERS_F = BASE / "peers.json"
DIRECT_SENT_F = BASE / "files" / "direct_sent.json"
LOG = BASE / "messages.log.jsonl"
HEALTH_F = BASE / "transport" / "health.json"
# Local diagnostics log: one small line per minute while the watcher
# is alive, plus one line per (re)start. Lives in home, so it survives
# a VM replacement that wipes /etc (where the systemd unit lives).
LIVENESS_F = BASE / "liveness.jsonl"
LIVENESS_STATE_F = BASE / "transport" / "liveness_state.json"
MAX_LIVENESS_BYTES = 5 * 1024 * 1024  # ~11 days of 60 s ticks
LIVENESS_GAP_SECS = 120  # a gap longer than this means the watcher was down
NTFY_BASE = "https://ntfy.envs.net"
NTFY_MIRROR = "https://ntfy.adminforge.de"
TYPES = ["handshake", "message", "ack", "ping", "heartbeat", "file",
         "task_request", "task_update", "task_result"]
_lock = threading.Lock()
# Optimisation constants (internal only; wire format unchanged).
DEDUP_CAP = 5000  # was 500: ntfy caches ~12h, anti-replay is 7 days
MAX_LOG_BYTES = 10 * 1024 * 1024  # rotate messages.log.jsonl past 10 MB
MAX_BLOB_BYTES = 50 * 1024 * 1024  # direct_file blob download cap
MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024  # small-file attachment cap
MAX_UNZIP_BYTES = 100 * 1024 * 1024  # total uncompressed zip cap
HTTP_RETRIES = 3
# Transport order for http(): "curl" (default) tries the curl binary
# first and falls back to urllib; "urllib" skips curl entirely.
# Set MUSEBOT_TRANSPORT=urllib to force the old path for a test.
TRANSPORT_PRIMARY = os.environ.get("MUSEBOT_TRANSPORT", "curl").lower()
# Circuit breaker: after N consecutive failures a base is cooled down
# for this long; publish/poll skip it until the cooldown expires
# (then one probe is allowed). Counts live in transport/health.json.
CIRCUIT_FAIL_THRESHOLD = 3
CIRCUIT_COOLDOWN_SECS = 300
MAX_RESEND_ATTEMPTS = 10  # was 20: after this, a message goes to dead-letter
# Noisy transport events are logged at most once per key per 30 s,
# so a failing stream cannot flood messages.log.jsonl (it hit 1250
# identical SSL lines in one hour on 2026-11-16).
_LOG_THROTTLE_SECS = 30
_THROTTLED_EVENTS = {"http_retry", "transport_failed", "transport_poll_failed",
                     "stream_reconnect", "transport_file_failed"}
_LOG_LAST: dict = {}
_CONFIG_CACHE: dict = {"mtime": None, "data": {}}
_PEERS_CACHE: dict = {"mtime": None, "data": None}
_STATE_CACHE: dict = {"data": None, "written": None}

def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

def now_ts():
    return datetime.now(timezone.utc).timestamp()

def config() -> dict:
    """Cached config: re-read only when config.json changed on disk."""
    try:
        mtime = (BASE / "config.json").stat().st_mtime_ns
    except Exception:
        return dict(_CONFIG_CACHE["data"])
    if _CONFIG_CACHE["mtime"] != mtime:
        try:
            _CONFIG_CACHE["data"] = json.loads((BASE / "config.json").read_text(encoding="utf-8"))
        except Exception:
            _CONFIG_CACHE["data"] = {}
        _CONFIG_CACHE["mtime"] = mtime
    return dict(_CONFIG_CACHE["data"])

def log(event, **fields):
    if event in _THROTTLED_EVENTS:
        key = (event, fields.get("url") or fields.get("base") or fields.get("topic")
               or fields.get("id") or "")
        last = _LOG_LAST.get(key, 0)
        if now_ts() - last < _LOG_THROTTLE_SECS:
            return
        _LOG_LAST[key] = now_ts()
    entry = {"ts": now_iso(), "event": event, **fields}
    with _lock:
        try:
            if LOG.exists() and LOG.stat().st_size > MAX_LOG_BYTES:
                for i in (2, 1):
                    old, new = LOG.with_suffix(f".jsonl.{i}"), LOG.with_suffix(f".jsonl.{i + 1}")
                    if old.exists():
                        shutil.move(str(old), str(new))
                shutil.move(str(LOG), str(LOG.with_suffix(".jsonl.1")))
        except Exception:
            pass
        with LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

# ---------------- peers ----------------

def load_peers():
    """Cached peer list: re-read/derive only when peers.json or config.json changed."""
    try:
        key = ((PEERS_F.stat().st_mtime_ns if PEERS_F.exists() else 0),
               ((BASE / "config.json").stat().st_mtime_ns if (BASE / "config.json").exists() else 0))
    except Exception:
        key = None
    if _PEERS_CACHE["data"] is not None and _PEERS_CACHE["mtime"] == key:
        return [dict(p) for p in _PEERS_CACHE["data"]]
    if PEERS_F.exists():
        peers = json.loads(PEERS_F.read_text(encoding="utf-8"))["peers"]
        for p in peers:
            if p.get("base_url") == NTFY_BASE and not p.get("mirror_base_url"):
                p["mirror_base_url"] = "https://ntfy.adminforge.de"
            if network_mode() and p.get("node_name"):
                # v6: topics/keys always re-derive from the current code,
                # so rotating the code updates every record at once.
                fresh = node_peer(p["node_name"], p.get("role"), p["peer_id"])
                keep = {k: p[k] for k in ("email", "aliases", "created_at") if p.get(k)}
                p.update(fresh); p.update(keep)
        _PEERS_CACHE["data"] = peers
        _PEERS_CACHE["mtime"] = key
        return [dict(p) for p in peers]
    _PEERS_CACHE["data"] = []
    _PEERS_CACHE["mtime"] = key
    return []

def save_peers(peers):
    PEERS_F.write_text(json.dumps({"peers": peers}, ensure_ascii=False, indent=2), encoding="utf-8")
    _PEERS_CACHE["data"] = None  # invalidate cache; next load_peers() re-reads

def get_peer(peer_id):
    for p in load_peers():
        if p["peer_id"] == peer_id:
            return p
    return None

def find_peer(ref):
    """Resolve a peer by id, label or alias (case-insensitive)."""
    if not ref:
        return None
    ref_l = ref.strip().lower()
    for p in load_peers():
        names = [p["peer_id"], p.get("label") or ""] + (p.get("aliases") or [])
        if any(n.lower() == ref_l for n in names if n):
            return p
    return None

def resolve_targets(to_arg):
    """'all', a single peer ref, or a comma-separated list of refs."""
    peers = load_peers()
    if not to_arg or to_arg.strip().lower() == "all":
        return peers
    out = []
    for ref in to_arg.split(","):
        p = find_peer(ref)
        if not p:
            print(json.dumps({"ok": False, "reason": f"unknown peer: {ref.strip()}"})); sys.exit(1)
        if p not in out:
            out.append(p)
    return out

# ---------------- outgoing task registry (master side) ----------------

OUTGOING_F = BASE / "tasks" / "outgoing.json"

def load_outgoing():
    try:
        return json.loads(OUTGOING_F.read_text(encoding="utf-8"))
    except Exception:
        return {}

def save_outgoing(reg):
    OUTGOING_F.parent.mkdir(parents=True, exist_ok=True)
    OUTGOING_F.write_text(json.dumps(reg, ensure_ascii=False, indent=2), encoding="utf-8")

def update_outgoing(message_id, **fields):
    with _lock:
        reg = load_outgoing()
        if message_id in reg:
            reg[message_id].update(fields); save_outgoing(reg)

def default_peer():
    peers = load_peers()
    return peers[0] if peers else None

# ---------------- crypto ----------------

def derive_key(master_b64, label):
    master = base64.b64decode(master_b64)
    return hmac_mod.new(master, label.encode(), hashlib.sha256).digest()

def aes_encrypt(key, data):
    nonce = os.urandom(12)
    return nonce, AESGCM(key).encrypt(nonce, data, None)

def aes_decrypt(key, nonce, ct):
    return AESGCM(key).decrypt(nonce, ct, None)

def self_role():
    return (config().get("self") or {}).get("role", "slave")

def self_name():
    return (config().get("self") or {}).get("node_name") or "peer-muse"

def out_label():
    # Legacy (v5) direction labels.
    return "relay-key:m2s" if self_role() == "master" else "relay-key:s2m"

# ---------------- network model (protocol v6) ----------------
# ONE short code = ONE network: exactly one master + any number of slaves.
# Every parameter derives from the code locally; nothing else is shared.
#   network key  K = SHA-256("musebot/v6/key:" + code)
#   announce topic = "musebot-" + hex(SHA-256("musebot/v6/announce:" + code))[:24]
#                    (heartbeats + handshake announcements; key HMAC(K, "relay-key:announce"))
#   node topic(name) = "musebot-" + hex(SHA-256("musebot/v6/node:" + code + ":" + name))[:24]
#                    (direct traffic to that node; key HMAC(K, "relay-key:<from>><to>"))

def network_code():
    return config().get("network_code")

def network_mode():
    return bool(network_code())

def net_key_bytes(code):
    return hashlib.sha256(("musebot/v6/key:" + normalize_code(code)).encode()).digest()

def announce_topic(code):
    return "musebot-" + hashlib.sha256(("musebot/v6/announce:" + normalize_code(code)).encode()).hexdigest()[:24]

def node_topic(code, name):
    return "musebot-" + hashlib.sha256(("musebot/v6/node:" + normalize_code(code) + ":" + name).encode()).hexdigest()[:24]

def pair_key(code, frm, to):
    return hmac_mod.new(net_key_bytes(code), f"relay-key:{frm}>{to}".encode(), hashlib.sha256).digest()

def announce_key(code):
    return hmac_mod.new(net_key_bytes(code), b"relay-key:announce", hashlib.sha256).digest()

def node_id(name):
    return "n-" + hashlib.sha256(name.encode()).hexdigest()[:8]

def node_peer(name, role=None, peer_id=None):
    """The peer record for one network node, fully derived from the code."""
    code = network_code()
    return {"peer_id": peer_id or node_id(name), "label": name, "node_name": name,
            "role": role, "network": True, "email": None,
            "base_url": NTFY_BASE, "mirror_base_url": NTFY_MIRROR,
            "topic_to_peer": node_topic(code, name),
            "topic_to_nicholas": node_topic(code, self_name()),
            "pairing_code": code,
            "encryption_key": base64.b64encode(net_key_bytes(code)).decode()}

def broadcast_peer():
    """Pseudo-peer for announce traffic (heartbeats, handshake announcements)."""
    p = node_peer("*")
    p["peer_id"] = "network"; p["topic_to_peer"] = announce_topic(network_code())
    return p

def find_peer_by_name(name):
    for p in load_peers():
        if (p.get("node_name") or p.get("label")) == name:
            return p
    return None

def msg_key(msg, peer):
    """Encryption key for an envelope, by model."""
    if peer.get("network"):
        code = network_code()
        if msg.get("to") == "*":
            return announce_key(code)
        return pair_key(code, msg.get("from") or "", msg.get("to") or "")
    return derive_key(peer["encryption_key"], out_label())

def wrap_envelope(msg, peer):
    if not AESGCM or not peer.get("encryption_key"):
        return msg
    key = msg_key(msg, peer)
    nonce, ct = aes_encrypt(key, json.dumps(msg, ensure_ascii=False).encode("utf-8"))
    return {"relay_version": 3, "encrypted": True, "id": msg["id"],
            "from": msg.get("from"), "to": msg.get("to"),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode()}

def unwrap_envelope(obj, peer):
    if isinstance(obj, dict) and obj.get("encrypted"):
        if not AESGCM or not peer.get("encryption_key"):
            raise ValueError("encrypted message but no key/crypto available")
        raw = base64.b64decode(obj["ciphertext"]); nonce = base64.b64decode(obj["nonce"])
        candidates = []
        if peer.get("network"):
            code = network_code(); frm = obj.get("from") or ""
            candidates = [pair_key(code, frm, self_name()), announce_key(code),
                          pair_key(code, frm, "*"), pair_key(code, self_name(), frm)]
        else:
            candidates = [derive_key(peer["encryption_key"], label) for label in
                          ("relay-key:m2s", "relay-key:s2m", "relay-key:p2n", "relay-key:n2p")]
        for key in candidates:
            try:
                return json.loads(aes_decrypt(key, nonce, raw).decode("utf-8"))
            except Exception:
                pass
        # v3.1 compatibility: the master key itself was used
        return json.loads(aes_decrypt(base64.b64decode(peer["encryption_key"]), nonce, raw).decode("utf-8"))
    return obj

def encrypt_file_bytes(peer, data, frm=None, to=None):
    if peer.get("network"):
        key = pair_key(network_code(), frm or self_name(), to or peer.get("node_name") or "")
    else:
        key = derive_key(peer["encryption_key"], out_label())
    nonce, ct = aes_encrypt(key, data)
    return nonce + ct

def decrypt_file_bytes(peer, raw, frm=None, to=None):
    keys = []
    if peer.get("network"):
        code = network_code()
        keys = [pair_key(code, frm or "", to or self_name()),
                pair_key(code, to or self_name(), frm or ""),
                announce_key(code)]
    else:
        keys = [derive_key(peer["encryption_key"], label) for label in
                ("relay-key:m2s", "relay-key:s2m", "relay-key:p2n", "relay-key:n2p")]
    for key in keys:
        try:
            return aes_decrypt(key, raw[:12], raw[12:])
        except Exception:
            pass
    return aes_decrypt(base64.b64decode(peer["encryption_key"]), raw[:12], raw[12:])

# ---------------- pairing codes ----------------

def gen_pairing_code():
    """A fresh network code: 'MB-' + 12 base32 chars (60 bits) in 3 groups
    of 4 - short enough to read aloud or type. The code IS the network:
    one master + any number of slaves, all parameters derived from it."""
    raw = base64.b32encode(secrets.token_bytes(8)).decode().rstrip("=")[:12]
    return "MB-" + "-".join(raw[i:i + 4] for i in range(0, 12, 4))

def normalize_code(code):
    c = "".join(ch for ch in str(code).upper() if ch.isalnum())
    if c.startswith("MB") and len(c) in (14, 26):
        c = c[2:]
    return c

# ---------------- state / presence ----------------

def load_state() -> dict:
    """In-memory state cache: one disk read per process unless the file changed."""
    if _STATE_CACHE["data"] is not None:
        return _STATE_CACHE["data"]
    try:
        s = json.loads(STATE_F.read_text(encoding="utf-8"))
    except Exception:
        s = {}
    s.setdefault("processed_ids", []); s.setdefault("acked_ids", [])
    s.setdefault("attempts", {}); s.setdefault("last_event", {})
    _STATE_CACHE["data"] = s
    return s

def save_state(s):
    s["processed_ids"] = s.get("processed_ids", [])[-DEDUP_CAP:]
    s["acked_ids"] = s.get("acked_ids", [])[-DEDUP_CAP:]
    data = json.dumps(s)
    if _STATE_CACHE["written"] == data:
        return  # unchanged: skip the disk write
    STATE_F.parent.mkdir(parents=True, exist_ok=True)
    STATE_F.write_text(data, encoding="utf-8")
    _STATE_CACHE["written"] = data
    _STATE_CACHE["data"] = s

def load_presence():
    try:
        return json.loads(PRESENCE_F.read_text(encoding="utf-8"))
    except Exception:
        return {}

def save_presence(p):
    PRESENCE_F.write_text(json.dumps(p, ensure_ascii=False, indent=2), encoding="utf-8")

def touch_presence(peer_id, kind):
    with _lock:
        p = load_presence()
        rec = p.get(peer_id, {})
        rec["last_" + kind] = now_iso(); rec["last_" + kind + "_ts"] = now_ts()
        p[peer_id] = rec; save_presence(p)

def peer_online(peer_id):
    rec = load_presence().get(peer_id, {})
    ts = max(rec.get("last_heartbeat_ts", 0), rec.get("last_message_ts", 0))
    return ts and (now_ts() - ts) < 12 * 60

# ---------------- transport health / circuit breaker ----------------

def load_health() -> dict:
    try:
        return json.loads(HEALTH_F.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_health(h):
    try:
        HEALTH_F.parent.mkdir(parents=True, exist_ok=True)
        HEALTH_F.write_text(json.dumps(h, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


def record_transport_success(base):
    h = load_health()
    rec = h.setdefault(base, {"ok": 0, "fail": 0, "consecutive_fail": 0,
                              "unhealthy_until": 0, "last_error": ""})
    rec["ok"] += 1
    rec["consecutive_fail"] = 0
    rec["unhealthy_until"] = 0
    rec["last_success"] = now_iso()
    save_health(h)


def record_transport_failure(base, error):
    h = load_health()
    rec = h.setdefault(base, {"ok": 0, "fail": 0, "consecutive_fail": 0,
                              "unhealthy_until": 0, "last_error": ""})
    rec["fail"] += 1
    rec["consecutive_fail"] = rec.get("consecutive_fail", 0) + 1
    rec["last_error"] = str(error)[:150]
    rec["last_failure"] = now_iso()
    if rec["consecutive_fail"] >= CIRCUIT_FAIL_THRESHOLD and not rec.get("unhealthy_until", 0) > now_ts():
        rec["unhealthy_until"] = now_ts() + CIRCUIT_COOLDOWN_SECS
        save_health(h)
        log("circuit_open", base=base, consecutive_fail=rec["consecutive_fail"],
            cooldown_secs=CIRCUIT_COOLDOWN_SECS, error=str(error)[:120])
        return
    save_health(h)


def base_healthy(base) -> bool:
    rec = load_health().get(base)
    if not rec:
        return True
    until = rec.get("unhealthy_until", 0) or 0
    return now_ts() >= until


def ordered_bases(peer):
    """Healthy bases first; cooling-down bases last (probe only)."""
    all_bases = bases(peer)
    healthy = [b for b in all_bases if base_healthy(b)]
    cooling = [b for b in all_bases if b not in healthy]
    return healthy + cooling


# ---------------- http ----------------

def _is_retryable(exc) -> bool:
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code in (429, 500, 502, 503, 504)
    return isinstance(exc, (urllib.error.URLError, ssl.SSLError, ConnectionError, TimeoutError, OSError))


def _http_via_curl(method, url, data=None, headers=None, timeout=30, max_bytes=None):
    """Fallback transport via the curl binary (no shell, list argv only).

    curl proved reliable on 2026-11-16 where Python urllib intermittently
    failed with SSL WRONG_VERSION_NUMBER / RemoteDisconnected through
    the egress proxy, while curl's CONNECT tunnel succeeded.
    Raises on non-2xx or a curl failure; returns raw bytes on success.
    """
    import shutil as _shutil
    curl = _shutil.which("curl")
    if not curl:
        raise ConnectionError("curl binary not available for fallback")
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tmp = tf.name
    try:
        argv = [curl, "-sS", "--max-time", str(timeout), "-X", method,
                "-o", tmp, "-w", "%{http_code}", url]
        for k, v in (headers or {}).items():
            argv += ["-H", f"{k}: {v}"]
        if data is not None:
            argv += ["--data-binary", "@-"]
        r = subprocess.run(argv, input=data, capture_output=True, timeout=timeout + 10)
        code = int((r.stdout or b"").decode().strip() or 0)
        if r.returncode != 0:
            raise ConnectionError(f"curl exit {r.returncode}: {(r.stderr or b'').decode(errors='replace')[:120]}")
        if code < 200 or code >= 300:
            raise urllib.error.HTTPError(url, code, f"curl HTTP {code}", {}, None)
        body = Path(tmp).read_bytes()
        if max_bytes is not None and len(body) > max_bytes:
            raise ValueError(f"response exceeds {max_bytes} bytes from {url}")
        log("http_curl", url=url, code=code)
        return body
    finally:
        try:
            Path(tmp).unlink()
        except Exception:
            pass


def http(method, url, data=None, headers=None, timeout=30, max_bytes=None, retries=HTTP_RETRIES):
    """One HTTP call with retries + exponential backoff + jitter.

    Primary transport is curl (TRANSPORT_PRIMARY="curl"): on
    2026-11-16 curl went 10/10 against ntfy while urllib went 9/10,
    and during the outage curl succeeded while urllib failed with
    SSL WRONG_VERSION_NUMBER through the egress proxy. If curl is
    missing or fails, urllib is tried with its usual retries.
    Retries only transient failures (5xx/429, network/SSL errors); a 4xx
    other than 429 fails fast. Reads in chunks so a hostile response
    cannot OOM the watcher when max_bytes is set.
    """
    if TRANSPORT_PRIMARY == "curl":
        try:
            return _http_via_curl(method, url, data=data, headers=headers,
                                  timeout=timeout, max_bytes=max_bytes)
        except Exception as curl_e:
            log("http_curl_primary_failed", url=url, error=str(curl_e)[:120])
    last_exc = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                if max_bytes is None:
                    return r.read()
                chunks, total = [], 0
                while True:
                    chunk = r.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise ValueError(f"response exceeds {max_bytes} bytes from {url}")
                    chunks.append(chunk)
                return b"".join(chunks)
        except Exception as e:  # noqa: BLE001 - retried / logged by caller
            last_exc = e
            if attempt >= retries or not _is_retryable(e):
                break
            delay = min(8.0, 1.0 * (2 ** attempt)) + random.random() * 0.5
            log("http_retry", url=url, attempt=attempt + 1, delay=round(delay, 2), error=str(e)[:120])
            time.sleep(delay)
    # urllib path exhausted. If curl was the primary it already
    # failed above, so there is nothing left to try; if the primary
    # was urllib, try curl once as a last resort.
    if TRANSPORT_PRIMARY != "curl":
        try:
            return _http_via_curl(method, url, data=data, headers=headers,
                                  timeout=timeout, max_bytes=max_bytes)
        except Exception as curl_e:
            log("http_curl_fallback_failed", url=url, error=str(curl_e)[:120])
    raise last_exc

def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

# ---------------- messages ----------------

def new_msg(peer, mtype, body, reply_to=None, attachments=None, task=None, direct_file=None):
    cfg = config()
    self_name = (cfg.get("self") or {}).get("node_name") or "peer-muse"
    return {"relay_version": 2, "pairing_code": peer["pairing_code"],
            "id": "msg-" + uuid.uuid4().hex[:16],
            "from": self_name, "to": peer.get("node_name") or "peer-muse",
            "from_role": (cfg.get("self") or {}).get("role"),
            "peer_id": peer["peer_id"],
            "type": mtype, "created_at": now_iso(), "reply_to": reply_to,
            "body": body, "owner_approved": True,
            "attachments": attachments or [], "task": task,
            "direct_file": direct_file}

def bases(peer):
    out = [peer["base_url"]]
    if peer.get("mirror_base_url"):
        out.append(peer["mirror_base_url"])
    return out

def publish_raw(peer, topic, data, headers=None, base=None):
    return http("POST", f"{base or peer['base_url']}/{topic}", data=data, headers=headers or {})

def transport_publish_envelope(msg, peer):
    ok_any = False
    candidates = ordered_bases(peer)
    # If a healthy base exists, do not waste attempts on cooling-down
    # bases: they only add log spam and delay. If none is healthy,
    # ordered_bases() returns the cooling ones as probes.
    if any(base_healthy(b) for b in bases(peer)):
        candidates = [b for b in candidates if base_healthy(b)]
    for base in candidates:
        try:
            body = json.dumps(wrap_envelope(msg, peer), ensure_ascii=False).encode("utf-8")
            publish_raw(peer, peer["topic_to_peer"], body,
                        {"Content-Type": "text/plain; charset=utf-8"}, base=base)
            record_transport_success(base)
            ok_any = True
        except Exception as e:
            record_transport_failure(base, e)
            log("transport_failed", id=msg["id"], peer=peer["peer_id"], base=base, error=str(e)[:150])
    if ok_any:
        log("transport_sent", id=msg["id"], peer=peer["peer_id"], encrypted=True)
    return ok_any

def transport_publish_file(peer, path: Path, msg_id):
    ok_any = False
    frm = to = None
    if peer.get("network"):
        try:
            m = json.loads((OUTBOX / f"{msg_id}.json").read_text(encoding="utf-8"))
            frm, to = m.get("from"), m.get("to")
        except Exception:
            pass
    candidates = ordered_bases(peer)
    if any(base_healthy(b) for b in bases(peer)):
        candidates = [b for b in candidates if base_healthy(b)]
    for base in candidates:
        try:
            data = path.read_bytes(); name = path.name
            if AESGCM and peer.get("encryption_key"):
                data = encrypt_file_bytes(peer, data, frm=frm, to=to); name = path.name + ".enc"
            http("PUT", f"{base}/{peer['topic_to_peer']}", data=data,
                 headers={"X-Filename": name, "X-Title": msg_id})
            record_transport_success(base)
            ok_any = True
        except Exception as e:
            record_transport_failure(base, e)
            log("transport_file_failed", id=msg_id, base=base, error=str(e)[:150])
    if ok_any:
        log("transport_file_sent", id=msg_id, peer=peer["peer_id"])
    return ok_any

def queue_outgoing(msg, peer):
    name = f"{msg['id']}.json"
    for folder in (OUTBOX, TO_PEER):
        folder.mkdir(parents=True, exist_ok=True)
        (folder / name).write_text(json.dumps(msg, ensure_ascii=False, indent=2), encoding="utf-8")
    log("sent", id=msg["id"], type=msg["type"], peer=peer["peer_id"])
    transport_publish_envelope(msg, peer)
    return name

def send_ack(peer, original_id):
    msg = new_msg(peer, "ack", f"Received {original_id}", reply_to=original_id)
    OUTBOX.mkdir(parents=True, exist_ok=True)
    (OUTBOX / f"{msg['id']}.json").write_text(json.dumps(msg, ensure_ascii=False, indent=2), encoding="utf-8")
    transport_publish_envelope(msg, peer)
    log("ack_sent", id=original_id, peer=peer["peer_id"])

def validate(msg, peer):
    if not isinstance(msg, dict):
        return "not a JSON object"
    if msg.get("relay_version") not in (1, 2):
        return "unsupported relay_version"
    if msg.get("pairing_code") != peer["pairing_code"]:
        return "pairing_code mismatch"
    for field in ("id", "from", "to", "type", "created_at", "body"):
        if not msg.get(field):
            return f"missing field: {field}"
    if msg.get("type") not in TYPES:
        return f"unknown type: {msg.get('type')}"
    if msg.get("type") in ("handshake", "message", "file", "task_request") \
            and msg.get("owner_approved") is not True:
        return "owner_approved is not true"
    if msg.get("type") == "task_request":
        task = msg.get("task") or {}
        if not task.get("title") or not task.get("details"):
            return "task_request missing task.title or task.details"
    try:
        created = datetime.fromisoformat(msg["created_at"]).timestamp()
        if created < now_ts() - 7 * 86400:
            return "message too old (anti-replay)"
        if created > now_ts() + 3600:
            return "message from the future (anti-replay)"
    except Exception:
        return "bad created_at"
    for att in msg.get("attachments") or []:
        if not att.get("name") or not att.get("sha256") or att.get("size") is None:
            return "attachment missing name, size or sha256"
    return None

def verify_and_store_attachments(msg, peer):
    atts = msg.get("attachments") or []
    if not atts:
        return None
    src_dir = FILES_FROM_PEER / msg["id"]
    for att in atts:
        if att.get("encrypted"):
            enc_file = src_dir / (att["name"] + ".enc"); plain_file = src_dir / att["name"]
            if enc_file.exists() and not plain_file.exists():
                try:
                    plain_file.write_bytes(decrypt_file_bytes(peer, enc_file.read_bytes(),
                                                              frm=msg.get("from"), to=msg.get("to")))
                    enc_file.unlink()
                except Exception as e:
                    return f"attachment decrypt failed: {att['name']}: {e}"
        f = src_dir / att["name"]
        if not f.exists():
            return f"attachment not found in transport: {att['name']}"
        if f.stat().st_size != att["size"]:
            return f"attachment size mismatch: {att['name']}"
        if sha256_of(f) != att["sha256"]:
            return f"attachment sha256 mismatch: {att['name']}"
    dest_dir = FILES_RECEIVED / msg["id"]; dest_dir.mkdir(parents=True, exist_ok=True)
    for att in atts:
        shutil.move(str(src_dir / att["name"]), dest_dir / att["name"])
    return None

def process_direct_file(msg, peer):
    """Download, decrypt, verify and unzip a direct_file payload.
    Returns None on success (or when there is no direct_file), or an
    error string. On success the temp download is deleted (cleanup)."""
    df = msg.get("direct_file")
    if not df:
        return None
    dest_dir = FILES_RECEIVED / msg["id"]
    marker = dest_dir / ".direct_done"
    if marker.exists():
        return None
    tmp = BASE / "transport" / f"direct-{msg['id']}.enc"
    try:
        ua = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
        data = http("GET", df["url"], headers=ua, timeout=120, max_bytes=MAX_BLOB_BYTES)
        if hashlib.sha256(data).hexdigest() != df["blob_sha256"] and b"tmpfiles.org/dl/" in data:
            # tmpfiles landing page: follow its real download link once
            import re
            m = re.search(rb'class="download" href="([^"]+)"', data)
            if m:
                data = http("GET", m.group(1).decode(), headers=ua, timeout=120)
        tmp.write_bytes(data)
        if hashlib.sha256(data).hexdigest() != df["blob_sha256"]:
            return "direct_file blob sha256 mismatch"
        key = base64.b64decode(df["key"])
        zip_bytes = aes_decrypt(key, data[:12], data[12:])
        if hashlib.sha256(zip_bytes).hexdigest() != df["zip_sha256"]:
            return "direct_file zip sha256 mismatch"
        zip_path = BASE / "transport" / f"direct-{msg['id']}.zip"
        zip_path.write_bytes(zip_bytes)
        dest_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(zip_path) as z:
            total = 0
            for info in z.infolist():
                # Reject symlinks/hardlinks and absolute paths (zip-slip).
                mode = (info.external_attr >> 16) & 0o170000
                if mode == 0o120000 or info.filename.startswith(("/", "\\")):
                    return f"unsafe zip member: {info.filename}"
                total += info.file_size
                if total > MAX_UNZIP_BYTES:
                    return "zip uncompressed size exceeds limit"
                target = (dest_dir / info.filename).resolve()
                if not str(target).startswith(str(dest_dir.resolve())):
                    return "unsafe path in zip"
            z.extractall(dest_dir)
        zip_path.unlink()  # cleanup temp zip
        marker.write_text(now_iso(), encoding="utf-8")
        log("direct_file_received", id=msg["id"], peer=peer["peer_id"])
        return None
    except Exception as e:
        return f"direct_file failed: {e}"
    finally:
        if tmp.exists():
            tmp.unlink()  # cleanup temp download either way

def record_ack(msg, peer):
    with _lock:
        s = load_state()
        if msg.get("reply_to") and msg["reply_to"] not in s["acked_ids"]:
            s["acked_ids"].append(msg["reply_to"]); save_state(s)
    if msg.get("reply_to"):
        reg = load_outgoing()
        entry = reg.get(msg["reply_to"])
        if entry and entry.get("status") == "sent":
            update_outgoing(msg["reply_to"], status="delivered", delivered_at=now_iso())
    # sender-side cleanup for direct files once the peer acks them
    try:
        reg = json.loads(DIRECT_SENT_F.read_text(encoding="utf-8")) if DIRECT_SENT_F.exists() else {}
        item = reg.get(msg.get("reply_to") or "")
        if item and not item.get("cleaned"):
            http_cli = "/opt/hatch/bin/remote-storage"
            import subprocess
            subprocess.run([http_cli, "delete-file", "--url", item["url"]],
                           capture_output=True, timeout=60)
            blob = Path(item.get("local_blob", ""))
            if blob.exists():
                blob.unlink()
            item["cleaned"] = True; reg[msg["reply_to"]] = item
            DIRECT_SENT_F.write_text(json.dumps(reg, ensure_ascii=False, indent=2), encoding="utf-8")
            log("direct_file_cleaned", id=msg["reply_to"])
    except Exception as e:
        log("direct_cleanup_failed", error=str(e)[:150])

def learn_node(msg):
    """v6: keep the node registry current from anything a node sends, and
    enforce the one-master rule: a second, different master is a conflict
    that the owner must hear about."""
    if not network_mode() or not msg.get("from") or msg["from"] == self_name():
        return
    name = msg["from"]; role = msg.get("from_role")
    peers = load_peers()
    cur = next((p for p in peers if (p.get("node_name") or p.get("label")) == name), None)
    if cur is None:
        peers.append(node_peer(name, role)); save_peers(peers)
        log("node_learned", node=name, role=role)
    elif role and cur.get("role") != role:
        cur["role"] = role; save_peers(peers)
    if role == "master":
        known = self_name() if self_role() == "master" else (config().get("self") or {}).get("master_name")
        if known and name != known:
            c = {"name": name, "known_master": known, "seen_at": now_iso()}
            (BASE / "transport" / "master_conflict.json").write_text(
                json.dumps(c, ensure_ascii=False, indent=2), encoding="utf-8")
            log("master_conflict", node=name, known_master=known)

def ingest_envelope(msg, peer, source_path=None, via_announce=False):
    """Validate and file one decrypted envelope. Returns True if filed."""
    err = validate(msg, peer)
    if err:
        log("rejected", id=msg.get("id"), reason=err, peer=peer["peer_id"]); return False
    if msg.get("from") == self_name():
        return False  # my own announce traffic coming back at me (v6 topics are shared)
    learn_node(msg)
    with _lock:
        s = load_state()
        if msg["id"] in s["processed_ids"]:
            log("duplicate_skipped", id=msg["id"], peer=peer["peer_id"])
            send_ack(peer, msg["id"])  # ack again; the first may have been lost
            return False
    if msg["type"] == "heartbeat":
        touch_presence(peer["peer_id"], "heartbeat")
        with _lock:
            s = load_state(); s["processed_ids"].append(msg["id"]); save_state(s)
        return True
    if msg["type"] == "ack":
        record_ack(msg, peer); touch_presence(peer["peer_id"], "message")
        with _lock:
            s = load_state(); s["processed_ids"].append(msg["id"]); save_state(s)
        return True
    err = verify_and_store_attachments(msg, peer)
    if not err:
        err = process_direct_file(msg, peer)
    if err:
        log("rejected", id=msg["id"], reason=err, peer=peer["peer_id"]); return False
    INBOX.mkdir(parents=True, exist_ok=True)
    (INBOX / f"{msg['id']}.json").write_text(json.dumps(msg, ensure_ascii=False, indent=2), encoding="utf-8")
    with _lock:
        s = load_state(); s["processed_ids"].append(msg["id"]); save_state(s)
    touch_presence(peer["peer_id"], "message")
    log("received", id=msg["id"], type=msg["type"], peer=peer["peer_id"])
    if msg["type"] == "task_result" and msg.get("reply_to"):
        update_outgoing(msg["reply_to"], status="completed", completed_at=now_iso(),
                        result=(msg.get("body") or "")[:2000],
                        result_attachments=[a.get("name") for a in msg.get("attachments") or []])
    if msg["type"] == "task_update" and msg.get("reply_to"):
        st = (msg.get("task") or {}).get("status")
        if st in ("approved", "rejected"):
            update_outgoing(msg["reply_to"],
                            status="accepted" if st == "approved" else "rejected",
                            decided_at=now_iso())
    if msg["type"] == "task_request":
        TASKS_IN.mkdir(parents=True, exist_ok=True)
        auto = (config().get("task_policy") or {}).get("mode") == "auto_execute"
        record = {"message_id": msg["id"], "peer_id": peer["peer_id"],
                  "status": "auto_approved" if auto else "pending_owner_approval",
                  "received_at": now_iso(), "from": msg["from"],
                  "task": msg["task"], "body": msg["body"]}
        (TASKS_IN / f"{msg['id']}.json").write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
        log("task_auto_approved" if auto else "task_pending_approval", id=msg["id"], peer=peer["peer_id"])
    if via_announce and msg["type"] == "handshake":
        # On the announce channel only the intended counterpart acks:
        # the master acks a slave's announcement; a slave acks its
        # master's. Everyone else just takes note of the new node.
        counterpart = (self_role() == "master" and msg.get("from_role") == "slave") or \
                      (self_role() == "slave" and msg.get("from_role") == "master")
        if counterpart:
            send_ack(peer, msg["id"])
    else:
        send_ack(peer, msg["id"])
    return True

def ingest_file(path: Path, peer=None):
    if not path.exists():
        log("rejected", file=str(path), reason="file not found"); return False
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
        if peer is None and network_mode() and isinstance(obj, dict) and obj.get("from"):
            peer = find_peer_by_name(obj["from"]) or node_peer(obj["from"])
        peer = peer or default_peer()
        msg = unwrap_envelope(obj, peer)
    except Exception as e:
        dest_dir = PROCESSED / "rejected"; dest_dir.mkdir(parents=True, exist_ok=True)
        shutil.move(str(path), dest_dir / path.name)
        log("rejected", file=path.name, reason=f"bad envelope: {e}"); return False
    ok = ingest_envelope(msg, peer)
    if path.exists():
        dest = INBOX if ok else (PROCESSED / "rejected")
        dest.mkdir(parents=True, exist_ok=True)
        if path.parent != dest:
            try:
                path.unlink()
            except Exception:
                pass
    return ok

# ---------------- receiving ----------------

def handle_event_net(ev, state, via):
    """v6 receive path: one announce topic + my own node topic. The sender
    is identified by the wrapper's clear 'from' field; all channel values
    derive from the network code."""
    if ev.get("event") != "message":
        return False
    att = ev.get("attachment")
    if att and ev.get("title"):
        dest = FILES_FROM_PEER / ev["title"]; dest.mkdir(parents=True, exist_ok=True)
        target = dest / att["name"]
        if not target.exists():
            try:
                target.write_bytes(http("GET", att["url"], timeout=60, max_bytes=MAX_ATTACHMENT_BYTES))
                log("transport_file_received", id=ev["title"], name=att["name"])
            except Exception as e:
                log("transport_file_download_failed", id=ev["title"], error=str(e)[:150])
        return False
    text = ev.get("message") or ""
    try:
        obj = json.loads(text)
        frm = obj.get("from")
        if not frm:
            return False
        sender = find_peer_by_name(frm) or node_peer(frm)
        msg = unwrap_envelope(obj, sender)
    except Exception:
        return False
    if not isinstance(msg, dict) or "pairing_code" not in msg:
        return False
    if via == "announce" and msg.get("type") not in ("heartbeat", "handshake") \
            and msg.get("to") not in (self_name(), "*"):
        return False
    if via == "direct" and msg.get("to") not in (self_name(), "*"):
        return False
    atts = msg.get("attachments") or []
    def arrived(a):
        d = FILES_FROM_PEER / msg["id"]
        return (d / a["name"]).exists() or (d / (a["name"] + ".enc")).exists()
    PENDING.mkdir(parents=True, exist_ok=True)
    f = PENDING / f"{sender['peer_id']}--{msg['id']}.json"
    if any(not arrived(a) for a in atts):
        f.write_text(json.dumps(msg, ensure_ascii=False), encoding="utf-8")
        return False
    if f.exists():
        f.unlink()
    return ingest_envelope(msg, sender, via_announce=(via == "announce"))

def poll_topic(topic, via, base=None):
    state = load_state(); total = 0
    all_bases = [base] if base else [NTFY_BASE, NTFY_MIRROR]
    if base is None and any(base_healthy(b) for b in all_bases):
        all_bases = [b for b in all_bases if base_healthy(b)]
    for b in all_bases:
        since = state.get("last_event", {}).get(topic + "@" + b) or "all"
        try:
            raw = http("GET", f"{b}/{topic}/json?poll=1&since={since}", timeout=30)
            record_transport_success(b)
        except Exception as e:
            record_transport_failure(b, e)
            log("transport_poll_failed", topic=topic, base=b, error=str(e)[:150]); continue
        for line in raw.decode("utf-8", "replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception:
                continue
            if handle_event_net(ev, state, via):
                total += 1
            if ev.get("id"):
                with _lock:
                    s = load_state(); s.setdefault("last_event", {})[topic + "@" + b] = ev["id"]; save_state(s)
    return total

def stream_topic(topic, via, base, stop_flag):
    failures = 0
    while not stop_flag.is_set():
        try:
            req = urllib.request.Request(f"{base}/{topic}/json")
            with urllib.request.urlopen(req, timeout=120) as r:
                failures = 0
                record_transport_success(base)
                log("stream_connected", topic=topic, base=base)
                for raw_line in r:
                    if stop_flag.is_set():
                        break
                    line = raw_line.decode("utf-8", "replace").strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                    except Exception:
                        continue
                    if ev.get("event") == "keepalive":
                        continue
                    handle_event_net(ev, load_state(), via)
                    if ev.get("id"):
                        with _lock:
                            s = load_state(); s.setdefault("last_event", {})[topic + "@" + base] = ev["id"]; save_state(s)
        except Exception as e:
            failures += 1
            record_transport_failure(base, e)
            delay = min(60.0, 5.0 * (2 ** min(failures - 1, 4))) + random.random()
            log("stream_reconnect", topic=topic, base=base, failures=failures,
                delay=round(delay, 1), error=str(e)[:120])
            try:
                poll_topic(topic, via, base)
            except Exception as poll_e:
                log("stream_poll_fallback_failed", topic=topic, base=base, error=str(poll_e)[:120])
            stop_flag.wait(delay)

def retry_pending():
    count = 0
    if not PENDING.exists():
        return 0
    for f in sorted(PENDING.glob("*.json")):
        try:
            peer_id, msg_id = f.stem.split("--", 1)
            peer = get_peer(peer_id) or default_peer()
            msg = json.loads(f.read_text(encoding="utf-8"))
            atts = msg.get("attachments") or []
            def arrived(a):
                d = FILES_FROM_PEER / msg["id"]
                return (d / a["name"]).exists() or (d / (a["name"] + ".enc")).exists()
            if any(not arrived(a) for a in atts):
                continue
            if ingest_envelope(msg, peer):
                count += 1
            f.unlink()
        except Exception as e:
            log("retry_pending_failed", file=f.name, error=str(e)[:150])
    return count

def heartbeat_once(peer):
    msg = new_msg(peer, "heartbeat", "presence heartbeat")
    transport_publish_envelope(msg, peer)

def resend_unacked():
    """Re-publish outgoing messages that have no ack yet (max
    MAX_RESEND_ATTEMPTS tries, only while younger than 12h, at most once
    per 2 minutes each). Past the cap the message is dead-lettered once
    in the log instead of being retried forever."""
    s = load_state(); acked = set(s.get("acked_ids", [])); attempts = s.get("attempts", {})
    changed = False
    for f in sorted(OUTBOX.glob("*.json")):
        try:
            msg = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if msg.get("type") in ("ack", "heartbeat") or msg["id"] in acked:
            continue
        att = attempts.get(msg["id"], {})
        if att.get("count", 0) >= MAX_RESEND_ATTEMPTS:
            if not att.get("dead_logged"):
                log("dead_letter", id=msg["id"], peer=peer["peer_id"] if (peer := get_peer(msg.get("peer_id") or "")) else "",
                    tries=att.get("count", 0), reason="no ack after max resends")
                attempts[msg["id"]] = {**att, "dead_logged": True}
                changed = True
            continue
        if now_ts() - att.get("last", 0) < 120:
            continue
        try:
            created = datetime.fromisoformat(msg["created_at"]).timestamp()
            if now_ts() - created > 12 * 3600:
                continue
        except Exception:
            pass
        peer = get_peer(msg.get("peer_id") or "")
        if peer is None:
            continue  # never reroute a message to a different peer
        # Count every attempt, success or failure: the old code only
        # counted successes, so a permanently failing publish was
        # retried every minute forever and never hit the dead-letter cap.
        ok = transport_publish_envelope(msg, peer)
        attempts[msg["id"]] = {"count": att.get("count", 0) + 1, "last": now_ts(),
                               "dead_logged": att.get("dead_logged", False)}
        changed = True
        if ok:
            log("resent_unacked", id=msg["id"], peer=peer["peer_id"], tries=attempts[msg["id"]]["count"])
    if changed:
        with _lock:
            s = load_state(); s["attempts"] = attempts; save_state(s)

# ---------------- local diagnostics log ----------------

def _read_first_line(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip().splitlines()[0]
    except Exception:
        return ""


def machine_info():
    """Machine identity for downtime analysis. No secrets: only ids
    and booleans, never proxy credentials or network codes."""
    boot_id = _read_first_line("/proc/sys/kernel/random/boot_id")
    machine_id = _read_first_line("/etc/machine-id")
    uptime_s = None
    try:
        uptime_s = float(Path("/proc/uptime").read_text().split()[0])
    except Exception:
        pass
    return {"boot_id": boot_id or None, "machine_id": machine_id or None,
            "hostname": socket.gethostname(), "uptime_s": uptime_s,
            "pid": os.getpid(), "python": sys.version.split()[0],
            "curl": bool(shutil.which("curl")),
            "proxy_env": bool(os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY"))}


def _liveness_state():
    try:
        return json.loads(LIVENESS_STATE_F.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_liveness_state(state):
    try:
        LIVENESS_STATE_F.parent.mkdir(parents=True, exist_ok=True)
        tmp = LIVENESS_STATE_F.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
        tmp.replace(LIVENESS_STATE_F)
    except Exception:
        pass


def _append_liveness(entry):
    try:
        if LIVENESS_F.exists() and LIVENESS_F.stat().st_size > MAX_LIVENESS_BYTES:
            shutil.move(str(LIVENESS_F), str(LIVENESS_F.with_suffix(".jsonl.1")))
        with LIVENESS_F.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass


def classify_startup(prev, info, gap_s):
    """Why did the watcher (re)start? Pure function, unit-tested.

    prev: previous liveness state (may be empty). gap_s: seconds since
    the last tick, None on first ever start.
    """
    if not prev or gap_s is None:
        return "first_start"
    if prev.get("boot_id") and info.get("boot_id") and prev["boot_id"] != info["boot_id"]:
        return "machine_reboot_or_replace"
    if gap_s <= LIVENESS_GAP_SECS:
        return "clean_restart"
    return "process_down"


def record_startup():
    """Called once when the watcher starts. Logs the verdict so a
    later `diagnose` can say whether the machine rebooted, the
    process died, or the restart was clean."""
    info = machine_info()
    prev = _liveness_state()
    gap_s = round(now_ts() - prev["last_tick_ts"]) if prev.get("last_tick_ts") else None
    verdict = classify_startup(prev, info, gap_s)
    entry = {"ts": now_iso(), "event": "startup", "verdict": verdict,
             "gap_s": gap_s, "prev_boot_id": prev.get("boot_id"),
             "machine_id_changed": bool(prev.get("machine_id") and info.get("machine_id")
                                       and prev["machine_id"] != info["machine_id"]),
             **info}
    _append_liveness(entry)
    log("watcher_startup", verdict=verdict, gap_s=gap_s,
        machine_id_changed=entry["machine_id_changed"])
    _save_liveness_state({"boot_id": info["boot_id"], "machine_id": info["machine_id"],
                          "last_tick_ts": now_ts()})
    return entry


def record_liveness_tick():
    """One 60 s heartbeat line: proves the watcher was alive at this
    instant, with enough context to judge the transport then."""
    info = machine_info()
    try:
        rss_mb = int(Path(f"/proc/{os.getpid()}/status").read_text().split("VmRSS:")[1].split()[0]) // 1024
    except Exception:
        rss_mb = None
    health = load_health()
    peers = load_peers()
    pres = load_presence()
    entry = {"ts": now_iso(), "event": "tick", "boot_id": info["boot_id"],
             "uptime_s": info["uptime_s"], "pid": info["pid"], "rss_mb": rss_mb,
             "peers_online": [pr["node_name"] for pr in peers if peer_online(pr["peer_id"])],
             "peers_offline": [pr["node_name"] for pr in peers if not peer_online(pr["peer_id"])],
             "outbox": len(list(OUTBOX.glob("*.json"))) if OUTBOX.exists() else 0,
             "health": {b: {"ok": h.get("ok", 0), "fail": h.get("fail", 0),
                            "consecutive_fail": h.get("consecutive_fail", 0)}
                        for b, h in health.items()}}
    _append_liveness(entry)
    _save_liveness_state({"boot_id": info["boot_id"], "machine_id": info["machine_id"],
                          "last_tick_ts": now_ts()})
    return entry


def classify_gap(prev_tick, next_tick):
    """Classify one gap between two consecutive liveness lines.
    Returns None for a normal (<=120 s) interval."""
    if not prev_tick or not next_tick:
        return None
    try:
        gap = (datetime.fromisoformat(next_tick["ts"]) - datetime.fromisoformat(prev_tick["ts"])).total_seconds()
    except Exception:
        return None
    if gap <= LIVENESS_GAP_SECS:
        return None
    if next_tick.get("event") == "startup":
        return {"start": prev_tick["ts"], "end": next_tick["ts"], "gap_s": round(gap),
                "cause": next_tick.get("verdict", "unknown"),
                "machine_id_changed": next_tick.get("machine_id_changed", False)}
    if prev_tick.get("boot_id") and next_tick.get("boot_id") and prev_tick["boot_id"] != next_tick["boot_id"]:
        cause = "machine_reboot_or_replace"
    else:
        cause = "process_down"
    return {"start": prev_tick["ts"], "end": next_tick["ts"], "gap_s": round(gap), "cause": cause,
            "machine_id_changed": False}


def cmd_diagnose(args):
    """Read the local diagnostics log and explain past downtime.

    Prints JSON: startup verdicts, every downtime gap with its
    classified cause, transport-error counts in the 5 minutes before
    each gap (a gap preceded by transport errors is likely the
    egress proxy, not the machine), and current status.
    """
    ticks = []
    try:
        for line in LIVENESS_F.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                ticks.append(json.loads(line))
            except Exception:
                continue
    except Exception:
        pass
    startups = [t for t in ticks if t.get("event") == "startup"]
    gaps = []
    for a, b in zip(ticks, ticks[1:]):
        g = classify_gap(a, b)
        if g:
            gaps.append(g)
    # Transport errors shortly before each gap: were we already
    # failing to reach ntfy when the watcher went quiet?
    err_ts = []
    try:
        for line in LOG.read_text(encoding="utf-8", errors="replace").splitlines()[-5000:]:
            if "WRONG_VERSION_NUMBER" in line or '"transport_failed"' in line:
                try:
                    err_ts.append(datetime.fromisoformat(json.loads(line)["ts"]))
                except Exception:
                    continue
    except Exception:
        pass
    for g in gaps:
        try:
            start = datetime.fromisoformat(g["start"])
            g["transport_errors_5min_before"] = sum(
                0 <= (start - e).total_seconds() <= 300 for e in err_ts)
        except Exception:
            g["transport_errors_5min_before"] = None
    info = machine_info()
    health = load_health()
    report = {
        "now": now_iso(), "boot_id": info["boot_id"], "uptime_s": info["uptime_s"],
        "machine_id": info["machine_id"], "pid": info["pid"],
        "watcher_running": True,  # diagnose itself runs, so the relay code is alive here
        "liveness_lines": len(ticks),
        "first_tick": ticks[0]["ts"] if ticks else None,
        "last_tick": ticks[-1]["ts"] if ticks else None,
        "startups": [{"ts": s["ts"], "verdict": s.get("verdict"),
                      "gap_s": s.get("gap_s"),
                      "machine_id_changed": s.get("machine_id_changed")} for s in startups],
        "downtime_gaps": gaps,
        "total_downtime_s": sum(g["gap_s"] for g in gaps),
        "health": health,
        "peers": [{"node_name": pr.get("node_name"),
                   "online": bool(peer_online(pr["peer_id"]))} for pr in load_peers()],
        "unacked": len([f for f in OUTBOX.glob("*.json")]) if OUTBOX.exists() else 0,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))


def cmd_watch(args):
    """Resident watcher (network v6 only).

    Streams the announce + own-node topics from the PRIMARY ntfy base
    only; the mirror is polled every 30 s as a fallback instead of
    running a second, duplicate stream for every topic.
    """
    if not network_mode():
        print(json.dumps({"ok": False, "reason": "network_mode is off: this build is v6 network only"}))
        sys.exit(1)
    record_startup()
    stop = threading.Event()
    threads = []
    code = network_code()
    topics = [(announce_topic(code), "announce"),
              (node_topic(code, self_name()), "direct")]
    for topic, via in topics:
        t = threading.Thread(target=stream_topic, args=(topic, via, NTFY_BASE, stop), daemon=True)
        t.start(); threads.append(t)
    print(f"watching network streams ({len(threads)}) + local folders", flush=True)
    last_beat = 0; last_resend = 0; last_mirror_poll = 0; last_tick = 0
    try:
        while True:
            for p in sorted(FROM_PEER.glob("*.json")):
                ingest_file(p)
            retry_pending()
            if now_ts() - last_tick > 60:
                record_liveness_tick(); last_tick = now_ts()
            if now_ts() - last_mirror_poll > 30:
                for topic, via in topics:
                    try:
                        poll_topic(topic, via, base=NTFY_MIRROR)
                    except Exception as e:
                        log("mirror_poll_failed", topic=topic, error=str(e)[:120])
                last_mirror_poll = now_ts()
            if now_ts() - last_beat > 300:
                heartbeat_once(broadcast_peer())
                last_beat = now_ts()
            if now_ts() - last_resend > 60:
                resend_unacked(); last_resend = now_ts()
            time.sleep(2)
    except KeyboardInterrupt:
        stop.set()

def resolve_peer(args):
    pid = getattr(args, "to", None) or getattr(args, "peer", None)
    peer = find_peer(pid) if pid else default_peer()
    if not peer:
        print(json.dumps({"ok": False, "reason": f"unknown peer: {pid}"})); sys.exit(1)
    return peer

def cmd_send(args):
    peer = resolve_peer(args)
    msg = new_msg(peer, args.type, args.body, reply_to=args.reply_to)
    name = queue_outgoing(msg, peer)
    print(json.dumps({"ok": True, "id": msg["id"], "peer": peer["peer_id"], "file": f"transport/to_peer/{name}"}, ensure_ascii=False))

def cmd_send_task(args):
    targets = resolve_targets(args.to)
    group_id = "grp-" + uuid.uuid4().hex[:10] if len(targets) > 1 else None
    sent = []
    reg = load_outgoing()
    for peer in targets:
        task = {"title": args.title, "details": args.details,
                "requested_deadline": args.deadline, "group_id": group_id}
        msg = new_msg(peer, "task_request", args.body or f"Task request: {args.title}", task=task)
        queue_outgoing(msg, peer)
        reg[msg["id"]] = {"group_id": group_id, "peer_id": peer["peer_id"],
                          "peer_label": peer.get("label"), "title": args.title,
                          "status": "sent", "created_at": now_iso(), "result": None}
        sent.append({"peer_id": peer["peer_id"], "message_id": msg["id"]})
    save_outgoing(reg)
    print(json.dumps({"ok": True, "group_id": group_id, "sent_to": sent}, ensure_ascii=False))

def cmd_dispatched(args):
    reg = load_outgoing()
    items = [{"message_id": mid, **e} for mid, e in reg.items()]
    items.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    print(json.dumps(items[:50], ensure_ascii=False, indent=2))

def cmd_rename_peer(args):
    peer = find_peer(args.peer)
    if not peer:
        print(json.dumps({"ok": False, "reason": f"unknown peer: {args.peer}"})); sys.exit(1)
    peer["label"] = args.label
    if args.alias:
        peer.setdefault("aliases", [])
        if args.alias not in peer["aliases"]:
            peer["aliases"].append(args.alias)
    peers = [peer if p["peer_id"] == peer["peer_id"] else p for p in load_peers()]
    save_peers(peers)
    print(json.dumps({"ok": True, "peer_id": peer["peer_id"], "label": peer["label"],
                      "aliases": peer.get("aliases", [])}, ensure_ascii=False))

def cmd_send_file(args):
    peer = resolve_peer(args)
    src = Path(args.file)
    if not src.exists():
        print(json.dumps({"ok": False, "reason": "file not found"})); sys.exit(1)
    if src.stat().st_size > 1_500_000:
        print(json.dumps({"ok": False, "reason": "file over ~1.5MB; use send-direct instead"})); sys.exit(1)
    msg = new_msg(peer, "file", args.body or f"Sharing file: {src.name}")
    dest_dir = FILES_TO_PEER / msg["id"]; dest_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest_dir / src.name)
    sent_dir = FILES_SENT / msg["id"]; sent_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, sent_dir / src.name)
    msg["attachments"] = [{"name": src.name, "size": src.stat().st_size,
                           "sha256": sha256_of(src), "encrypted": bool(AESGCM and peer.get("encryption_key"))}]
    transport_publish_file(peer, src, msg["id"])
    queue_outgoing(msg, peer)
    print(json.dumps({"ok": True, "id": msg["id"], "peer": peer["peer_id"], "attachment": msg["attachments"][0]}, ensure_ascii=False))

def cmd_send_direct(args):
    """Large-file path: zip -> encrypt with a fresh per-file key ->
    upload blob to Muse storage -> send direct_file field in an
    encrypted envelope. Receiver cleans its temp files after unzip;
    we delete the remote blob when its ack arrives."""
    import subprocess
    peer = resolve_peer(args)
    sources = [Path(p) for p in args.paths]
    for s in sources:
        if not s.exists():
            print(json.dumps({"ok": False, "reason": f"not found: {s}"})); sys.exit(1)
    msg = new_msg(peer, "file", args.body or "Sharing large file(s) by direct link.")
    work = BASE / "transport" / f"pack-{msg['id']}"; work.mkdir(parents=True, exist_ok=True)
    zip_path = work / "payload.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for s in sources:
            if s.is_dir():
                for fp in s.rglob("*"):
                    if fp.is_file():
                        z.write(fp, fp.relative_to(s.parent))
            else:
                z.write(s, s.name)
    zip_bytes = zip_path.read_bytes()
    file_key = AESGCM.generate_key(bit_length=256)
    nonce, ct = aes_encrypt(file_key, zip_bytes)
    blob = work / "payload.enc"; blob.write_bytes(nonce + ct)
    out = subprocess.run(["/opt/hatch/bin/remote-storage", "upload-file",
                          "--path", str(blob), "--ttl-hours", "48"],
                         capture_output=True, text=True, timeout=300)
    try:
        result = json.loads(out.stdout.strip().splitlines()[-1])
        url = result["url"]
    except Exception:
        print(json.dumps({"ok": False, "reason": "upload failed", "detail": (out.stdout + out.stderr)[:300]})); sys.exit(1)
    df = {"url": url, "name": "payload.zip", "archive": "zip",
          "key": base64.b64encode(file_key).decode(),
          "blob_sha256": hashlib.sha256(nonce + ct).hexdigest(),
          "zip_sha256": hashlib.sha256(zip_bytes).hexdigest(),
          "zip_size": len(zip_bytes), "expires": result.get("expires_at")}
    msg["direct_file"] = df
    reg = json.loads(DIRECT_SENT_F.read_text(encoding="utf-8")) if DIRECT_SENT_F.exists() else {}
    reg[msg["id"]] = {"url": url, "local_blob": str(blob), "cleaned": False}
    DIRECT_SENT_F.parent.mkdir(parents=True, exist_ok=True)
    DIRECT_SENT_F.write_text(json.dumps(reg, ensure_ascii=False, indent=2), encoding="utf-8")
    queue_outgoing(msg, peer)
    print(json.dumps({"ok": True, "id": msg["id"], "peer": peer["peer_id"], "url": url,
                      "zip_size": len(zip_bytes)}, ensure_ascii=False))

def cmd_ingest(args):
    peer = get_peer(args.peer) if args.peer else default_peer()
    ok = ingest_file(Path(args.file), peer)
    print(json.dumps({"ok": ok})); sys.exit(0 if ok else 1)

def cmd_list(args):
    folder = {"inbox": INBOX, "outbox": OUTBOX, "to_peer": TO_PEER}[args.box]
    items = []
    for p in sorted(folder.glob("*.json")):
        m = json.loads(p.read_text(encoding="utf-8"))
        items.append({"id": m.get("id"), "peer_id": m.get("peer_id"), "from": m.get("from"),
                      "type": m.get("type"), "created_at": m.get("created_at"),
                      "body": (m.get("body") or "")[:120],
                      "attachments": [a.get("name") for a in m.get("attachments") or []],
                      "direct_file": bool(m.get("direct_file"))})
    print(json.dumps(items, ensure_ascii=False, indent=2))

def cmd_tasks(args):
    TASKS_IN.mkdir(parents=True, exist_ok=True)
    items = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(TASKS_IN.glob("*.json"))]
    print(json.dumps(items, ensure_ascii=False, indent=2))

def set_task_status(args, status):
    record_path = TASKS_IN / f"{args.message_id}.json"
    if not record_path.exists():
        print(json.dumps({"ok": False, "reason": "unknown task message id"})); sys.exit(1)
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["status"] = status; record["decided_at"] = now_iso()
    record_path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    peer = get_peer(record.get("peer_id") or "") or default_peer()
    msg = new_msg(peer, "task_update", f"Task '{record['task']['title']}' was {status} by {self_name()}.",
                  reply_to=args.message_id)
    msg["task"] = {"title": record["task"]["title"], "status": status}
    queue_outgoing(msg, peer)
    print(json.dumps({"ok": True, "task": args.message_id, "status": status}, ensure_ascii=False))

def cmd_send_result(args):
    peer = resolve_peer(args)
    msg = new_msg(peer, "task_result", args.body, reply_to=args.task_id)
    if args.file:
        src = Path(args.file)
        if not src.exists():
            print(json.dumps({"ok": False, "reason": "result file not found"})); sys.exit(1)
        msg["attachments"] = [{"name": src.name, "size": src.stat().st_size,
                               "sha256": sha256_of(src), "encrypted": bool(AESGCM and peer.get("encryption_key"))}]
        transport_publish_file(peer, src, msg["id"])
    queue_outgoing(msg, peer)
    # mark the task record completed when we know it
    record_path = TASKS_IN / f"{args.task_id}.json"
    if record_path.exists():
        record = json.loads(record_path.read_text(encoding="utf-8"))
        record["status"] = "completed"; record["result_message_id"] = msg["id"]
        record_path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"ok": True, "id": msg["id"], "peer": peer["peer_id"]}, ensure_ascii=False))

def cmd_peers(args):
    presence = load_presence(); state = load_state()
    out = []
    for p in load_peers():
        rec = presence.get(p["peer_id"], {})
        out.append({"peer_id": p["peer_id"], "label": p.get("label"), "email": p.get("email"),
                    "online": bool(peer_online(p["peer_id"])),
                    "last_heartbeat": rec.get("last_heartbeat"),
                    "last_message": rec.get("last_message"),
                    "connected": any(True for _ in [1]) and (rec.get("last_message") is not None)})
    print(json.dumps(out, ensure_ascii=False, indent=2))

def cmd_add_peer(args):
    """Register a known node (name + role) in the local registry. In the
    network model there are no per-node secrets to generate: the node
    joins with the shared network code, and this entry is learned
    automatically from its traffic anyway."""
    peers = load_peers()
    if find_peer_by_name(args.node_name or args.peer_id):
        print(json.dumps({"ok": False, "reason": "node already registered"})); sys.exit(1)
    peer = node_peer(args.node_name or args.peer_id, args.role or "slave", args.peer_id)
    if args.email:
        peer["email"] = args.email
    peers.append(peer); save_peers(peers)
    print(json.dumps({"ok": True, "peer_id": peer["peer_id"], "node_name": peer["node_name"]},
                     ensure_ascii=False))

def cmd_pairing(args):
    """No pairing card anymore: the network code alone is the credential.
    Print it so the owner can pass it on."""
    code = network_code()
    if not code:
        print(json.dumps({"ok": False, "reason": "no network code set (run join or new-code first)"})); sys.exit(1)
    print(code)
    print("Deploy with this code: run relay.py join, enter the code, a node name, and a role (master or slave).")

def cmd_rotate(args):
    """Rotate = start a fresh network code. Every node must re-join with
    the new code; the old code stops working immediately."""
    code = gen_pairing_code()
    cfg = config(); cfg["network_code"] = code
    (BASE / "config.json").write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"ok": True, "network_code": code,
                      "note": "all nodes must re-join with this code"}, ensure_ascii=False))

def cmd_handshake(args):
    """Announce this node on the network announce channel."""
    peer = broadcast_peer()
    hs = new_msg(peer, "handshake",
                 f"Hello, this is {self_role()} node '{self_name()}' joining the MuseBot "
                 "network (protocol v6). If your owner approves, ack this message.")
    queue_outgoing(hs, peer)
    print(json.dumps({"ok": True, "handshake_id": hs["id"]}, ensure_ascii=False))

def cmd_new_code(args):
    print(gen_pairing_code())

def scan_announce_masters(code, my_name):
    """Best-effort uniqueness check: read the announce channel cache and
    list any OTHER node currently claiming the master role."""
    found = set()
    topic = announce_topic(code); key = announce_key(code)
    for base in (NTFY_BASE, NTFY_MIRROR):
        try:
            raw = http("GET", f"{base}/{topic}/json?poll=1&since=all", timeout=20)
        except Exception:
            continue
        for line in raw.decode("utf-8", "replace").splitlines():
            try:
                ev = json.loads(line)
                if ev.get("event") != "message":
                    continue
                obj = json.loads(ev.get("message") or "")
                if not obj.get("encrypted"):
                    continue
                raw_ct = base64.b64decode(obj["ciphertext"]); nonce = base64.b64decode(obj["nonce"])
                msg = json.loads(aes_decrypt(key, nonce, raw_ct).decode("utf-8"))
                if msg.get("from_role") == "master" and msg.get("from") != my_name:
                    found.add(msg["from"])
            except Exception:
                continue
    return sorted(found)

def cmd_join(args):
    """The whole deployment input: the network code, this node's name,
    and its role. One network has exactly ONE master - enforced here by
    scanning the announce channel, and continuously by every watcher."""
    code = args.code or input("Network code (MB-....): ").strip()
    name = args.name or input("This node's name: ").strip()
    role = args.role or input("Role - master or slave: ").strip().lower()
    if role not in ("master", "slave"):
        print(json.dumps({"ok": False, "reason": "role must be master or slave"})); sys.exit(1)
    code = code.strip()
    if role == "master":
        others = scan_announce_masters(code, name)
        if others:
            print(json.dumps({"ok": False,
                              "reason": f"this network already has a master: {', '.join(others)}. "
                                        "A network can have only one master - join as slave, "
                                        "or use a different network code."}, ensure_ascii=False))
            sys.exit(1)
    cfg = config()
    cfg["network_code"] = code
    cfg["self"] = {"node_name": name, "role": role,
                   "master_name": name if role == "master" else (args.master_name or cfg.get("self", {}).get("master_name"))}
    cfg.setdefault("relay_id", "musebot-01")
    (BASE / "config.json").write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"ok": True, "self": cfg["self"],
                      "next": ["python3 relay.py watch   (resident service)",
                               "python3 relay.py handshake   (announce yourself on the network)"]},
                     ensure_ascii=False, indent=2))

def cmd_check_work(args):
    """Zero-token check used by the event hook: is there anything the
    agent processing loop needs to do right now?

    Fast path: if the inbox/tasks/outbox directories have not changed
    since the last check and there are no pending group dispatches,
    skip the full scan (the old code re-read every file on every run).
    """
    reasons = []
    try:
        st0 = json.loads((BASE / "processing_state.json").read_text(encoding="utf-8"))
    except Exception:
        st0 = {}
    def _dirs_mtime():
        m = 0
        for d in (TASKS_IN, INBOX, OUTBOX):
            try:
                m = max(m, d.stat().st_mtime_ns)
                for p in d.iterdir():
                    m = max(m, p.stat().st_mtime_ns)
            except Exception:
                pass
        return m
    _mt = _dirs_mtime()
    if _mt and st0.get("dirs_mtime") == _mt and not load_outgoing():
        print(json.dumps({"work": False, "reasons": []}, ensure_ascii=False))
        return
    st0["dirs_mtime"] = _mt
    try:
        (BASE / "processing_state.json").write_text(json.dumps(st0), encoding="utf-8")
    except Exception:
        pass
    try:
        st = json.loads((BASE / "processing_state.json").read_text(encoding="utf-8"))
    except Exception:
        st = {}
    executed = set(st.get("executed", [])); reported = set(st.get("reported", []))
    groups_reported = set(st.get("groups_reported", []))
    connected_reported = set(st.get("connected_reported", []))
    if TASKS_IN.exists():
        for p in TASKS_IN.glob("*.json"):
            try:
                r = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            if r.get("status") == "auto_approved" and r.get("message_id") not in executed:
                reasons.append(f"new_task:{r.get('message_id')}")
    if INBOX.exists():
        for p in INBOX.glob("*.json"):
            try:
                m = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            if m.get("id") not in reported and m.get("type") in ("message", "file", "handshake", "task_result"):
                reasons.append(f"new_inbox:{m.get('type')}:{m.get('id')}")
    reg = load_outgoing()
    by_group = {}
    for mid, e in reg.items():
        if e.get("group_id"):
            by_group.setdefault(e["group_id"], []).append((mid, e))
        elif e.get("status") in ("completed", "rejected") and mid not in reported:
            reasons.append(f"task_outcome:{mid}:{e.get('status')}")
    for gid, members in by_group.items():
        if gid in groups_reported:
            continue
        if all(e.get("status") in ("completed", "rejected") for _, e in members):
            reasons.append(f"group_done:{gid}")
        else:
            try:
                first = min(datetime.fromisoformat(e["created_at"]).timestamp() for _, e in members)
                if now_ts() - first > 3600 and any(e.get("status") == "completed" for _, e in members):
                    reasons.append(f"group_partial:{gid}")
            except Exception:
                pass
    # Genuine connection signals only: the node's watcher is sending
    # heartbeats, or we actually RECEIVED an ack from that node replying
    # to one of our handshakes. Local bookkeeping and stray messages
    # never count.
    if (BASE / "transport" / "master_conflict.json").exists():
        reasons.append("master_conflict")
    presence = load_presence()
    my_handshakes = set()
    if OUTBOX.exists():
        for p in OUTBOX.glob("*.json"):
            try:
                m = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            if m.get("type") == "handshake":
                my_handshakes.add(m.get("id"))
    acked_by = set()
    for folder in (BASE / "processed", INBOX):
        if folder.exists():
            for p in folder.glob("*.json"):
                try:
                    m = json.loads(p.read_text(encoding="utf-8"))
                except Exception:
                    continue
                if m.get("type") == "ack" and m.get("reply_to") in my_handshakes and m.get("from"):
                    acked_by.add(m["from"])
    for p in load_peers():
        if p["peer_id"] in connected_reported:
            continue
        rec = presence.get(p["peer_id"], {})
        if rec.get("last_heartbeat") or (p.get("node_name") or p.get("label")) in acked_by:
            reasons.append(f"peer_connected:{p['peer_id']}")
    print(json.dumps({"work": bool(reasons), "reasons": reasons}, ensure_ascii=False))

def cmd_poll(args):
    # Poll in threads with a hard join deadline: a stalled proxy layer
    # must not block the processing loop (the watcher streams anyway).
    if not network_mode():
        print(json.dumps({"ok": False, "reason": "network_mode is off: this build is v6 network only"}))
        sys.exit(1)
    code = network_code()
    results = {}

    def run_topic(topic, via):
        try:
            results[topic] = poll_topic(topic, via)
        except Exception as e:
            log("transport_poll_failed", topic=topic, error=str(e)[:150])
            results[topic] = 0

    threads = [threading.Thread(target=run_topic, args=(t, v), daemon=True)
               for t, v in [(announce_topic(code), "announce"),
                            (node_topic(code, self_name()), "direct")]]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=45)
    total = sum(results.values()) + retry_pending()
    print(json.dumps({"ok": True, "ingested": total}))


# ---------------- doctor ----------------

def _timed(fn):
    t0 = time.monotonic()
    try:
        ok, detail = fn()
        return {"ok": bool(ok), "detail": detail, "ms": round((time.monotonic() - t0) * 1000)}
    except Exception as e:
        return {"ok": False, "detail": str(e)[:150], "ms": round((time.monotonic() - t0) * 1000)}


def _urllib_get(url, timeout=10):
    """Raw urllib GET, no curl fallback: shows whether the Python
    path itself works. Returns (ok, status-or-error)."""
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        r.read(4096)
        return True, r.status


def _curl_get(url, timeout=10):
    """curl GET via the binary. Returns (ok, status-or-error)."""
    import shutil as _shutil
    curl = _shutil.which("curl")
    if not curl:
        return False, "curl binary not found"
    r = subprocess.run([curl, "-sS", "--max-time", str(timeout), "-o", "/dev/null",
                        "-w", "%{http_code}", url],
                       capture_output=True, timeout=timeout + 10)
    code = int((r.stdout or b"").decode().strip() or 0)
    if r.returncode != 0:
        return False, (r.stderr or b"").decode(errors="replace")[:120]
    return (200 <= code < 300), code


def cmd_doctor(args):
    """Diagnose the transport layer, layer by layer.

    For each ntfy base it tests DNS, TCP :443, direct TLS, raw-urllib
    GET /v1/health and curl GET /v1/health, plus one publish+poll
    round-trip on a throwaway doctor topic. It also reports peer
    presence, unacked outgoing messages and log counts, and a verdict:
    healthy / proxy_flaky (urllib fails, curl works) / bases_down.
    Nothing here changes wire format, keys or config.
    """
    import platform
    report = {"relay_id": config().get("relay_id"), "self": self_name(),
              "python": platform.python_version(),
              "curl_available": bool(__import__("shutil").which("curl")),
              "proxy_env_present": any(k.lower() in ("http_proxy", "https_proxy", "all_proxy")
                                       for k in os.environ),
              "bases": {}, "peers": [], "unacked": [], "log": {}, "health": load_health()}
    for base in [NTFY_BASE, NTFY_MIRROR]:
        host = urlparse(base).hostname
        res = {"base": base, "healthy": base_healthy(base)}
        res["dns"] = _timed(lambda h=host: (True, socket.getaddrinfo(h, 443, proto=socket.IPPROTO_TCP)[0][4][0]))
        res["tcp443"] = _timed(lambda h=host: (True, socket.create_connection((h, 443), timeout=5).close() or "connected"))
        def _tls(h=host):
            ctx = ssl.create_default_context()
            with socket.create_connection((h, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=h) as ssock:
                    return True, ssock.version()
        res["tls_direct"] = _timed(_tls)
        res["urllib_health"] = _timed(lambda b=base: _urllib_get(f"{b}/v1/health", timeout=10))
        res["curl_health"] = _timed(lambda b=base: _curl_get(f"{b}/v1/health", timeout=10))
        # Publish + poll round-trip on a throwaway topic (small, unencrypted).
        topic = f"musebot-doctor-{config().get('relay_id', 'x')}"
        def _pub(b=base, t=topic):
            body = json.dumps({"doctor": "ping", "ts": now_iso()}).encode()
            http("POST", f"{b}/{t}", data=body, headers={"Content-Type": "application/json"}, timeout=15, retries=0)
            raw = http("GET", f"{b}/{t}/json?poll=1&since=all", timeout=15, retries=0)
            return b"doctor" in raw, "published+polled"
        res["publish_poll"] = _timed(_pub)
        report["bases"][base] = res
    for peer in load_peers():
        pres = load_presence().get(peer["peer_id"], {})
        report["peers"].append({
            "node_name": peer.get("node_name"), "peer_id": peer["peer_id"],
            "online": bool(peer_online(peer["peer_id"])),
            "last_heartbeat_age_s": round(now_ts() - pres.get("last_heartbeat_ts", 0)) if pres.get("last_heartbeat_ts") else None,
            "last_message_age_s": round(now_ts() - pres.get("last_message_ts", 0)) if pres.get("last_message_ts") else None})
    s_state = load_state()
    acked = set(s_state.get("acked_ids", []))
    attempts = s_state.get("attempts", {})
    for f in sorted(OUTBOX.glob("*.json")):
        try:
            m = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if m["id"] in acked or m.get("type") in ("ack", "heartbeat"):
            continue
        report["unacked"].append({"id": m["id"], "type": m.get("type"),
                                   "age_s": round(now_ts() - datetime.fromisoformat(m["created_at"]).timestamp()),
                                   "tries": attempts.get(m["id"], {}).get("count", 0)})
    try:
        lines = LOG.read_text(encoding="utf-8", errors="replace").splitlines()[-5000:]
        report["log"] = {
            "ssl_wrong_version": sum("WRONG_VERSION_NUMBER" in l for l in lines),
            "transport_sent": sum('"transport_sent"' in l for l in lines),
            "transport_failed": sum('"transport_failed"' in l for l in lines),
            "circuit_open": sum('"circuit_open"' in l for l in lines),
            "curl_fallback": sum('"http_curl_fallback"' in l or '"http_curl"' in l for l in lines),
            "lines_scanned": len(lines)}
    except Exception as e:
        report["log"] = {"error": str(e)[:120]}
    # Verdict: the commonest real cause on 2026-11-16 was the egress
    # proxy breaking urllib's TLS while curl's CONNECT tunnel worked.
    verdicts = []
    for base, r in report["bases"].items():
        if r["urllib_health"]["ok"] and r["curl_health"]["ok"]:
            verdicts.append("healthy")
        elif not r["urllib_health"]["ok"] and r["curl_health"]["ok"]:
            verdicts.append("proxy_flaky")
        else:
            verdicts.append("bases_down")
    report["verdict"] = ("healthy" if all(v == "healthy" for v in verdicts)
                         else "proxy_flaky" if "proxy_flaky" in verdicts else "bases_down")
    report["verdict_note"] = {
        "healthy": "Both ntfy bases answer urllib and curl.",
        "proxy_flaky": "urllib fails but curl works on at least one base: the egress proxy is breaking Python's TLS (WRONG_VERSION_NUMBER); curl fallback in http() covers it.",
        "bases_down": "Both urllib and curl fail: ntfy bases or the whole egress path is down; check the proxy / network, not the relay code.",
    }[report["verdict"]]
    print(json.dumps(report, ensure_ascii=False, indent=2))


def cmd_status(args):
    cfg = config()
    def count(folder, pattern="*.json"):
        return len(list(folder.glob(pattern))) if folder.exists() else 0
    print(json.dumps({
        "relay_id": cfg["relay_id"], "protocol_version": 6,
        "network": bool(cfg.get("network_code")),
        "self": cfg.get("self"),
        "peers": [{"peer_id": p["peer_id"], "node_name": p.get("node_name"), "role": p.get("role"),
                   "online": bool(peer_online(p["peer_id"]))} for p in load_peers()],
        "inbox": count(INBOX), "outbox": count(OUTBOX),
        "tasks_auto_approved_waiting": sum(
            1 for p in TASKS_IN.glob("*.json")
            if json.loads(p.read_text(encoding="utf-8")).get("status") == "auto_approved")
        if TASKS_IN.exists() else 0,
    }, ensure_ascii=False, indent=2))

def main():
    ap = argparse.ArgumentParser(description="MuseBot relay (network model, protocol v6)")
    sub = ap.add_subparsers(required=True)
    s = sub.add_parser("send"); s.add_argument("--body", required=True)
    s.add_argument("--type", default="message", choices=TYPES); s.add_argument("--reply-to")
    s.add_argument("--to"); s.set_defaults(fn=cmd_send)
    st = sub.add_parser("send-task"); st.add_argument("--title", required=True)
    st.add_argument("--details", required=True); st.add_argument("--body")
    st.add_argument("--deadline"); st.add_argument("--to"); st.set_defaults(fn=cmd_send_task)
    sf = sub.add_parser("send-file"); sf.add_argument("file"); sf.add_argument("--body")
    sf.add_argument("--to"); sf.set_defaults(fn=cmd_send_file)
    sd = sub.add_parser("send-direct"); sd.add_argument("paths", nargs="+")
    sd.add_argument("--body"); sd.add_argument("--to"); sd.set_defaults(fn=cmd_send_direct)
    i = sub.add_parser("ingest"); i.add_argument("file"); i.add_argument("--peer"); i.set_defaults(fn=cmd_ingest)
    l = sub.add_parser("list"); l.add_argument("--box", default="inbox", choices=["inbox", "outbox", "to_peer"]); l.set_defaults(fn=cmd_list)
    t = sub.add_parser("tasks"); t.set_defaults(fn=cmd_tasks)
    ta = sub.add_parser("task-approve"); ta.add_argument("message_id"); ta.set_defaults(fn=lambda a: set_task_status(a, "approved"))
    tr = sub.add_parser("task-reject"); tr.add_argument("message_id"); tr.set_defaults(fn=lambda a: set_task_status(a, "rejected"))
    sr = sub.add_parser("send-result"); sr.add_argument("--task-id", required=True)
    sr.add_argument("--body", required=True); sr.add_argument("--file"); sr.add_argument("--to"); sr.set_defaults(fn=cmd_send_result)
    pe = sub.add_parser("peers"); pe.set_defaults(fn=cmd_peers)
    di = sub.add_parser("dispatched"); di.set_defaults(fn=cmd_dispatched)
    rp = sub.add_parser("rename-peer"); rp.add_argument("peer"); rp.add_argument("--label", required=True)
    rp.add_argument("--alias"); rp.set_defaults(fn=cmd_rename_peer)
    ap_ = sub.add_parser("add-peer"); ap_.add_argument("peer_id"); ap_.add_argument("--label"); ap_.add_argument("--email")
    ap_.add_argument("--node-name"); ap_.add_argument("--role", choices=["master", "slave"]); ap_.set_defaults(fn=cmd_add_peer)
    pb = sub.add_parser("pairing"); pb.add_argument("--to"); pb.add_argument("--handshake-id"); pb.set_defaults(fn=cmd_pairing)
    ro = sub.add_parser("rotate"); ro.add_argument("--to"); ro.set_defaults(fn=cmd_rotate)
    nc = sub.add_parser("new-code"); nc.set_defaults(fn=cmd_new_code)
    hk = sub.add_parser("handshake"); hk.add_argument("--to"); hk.set_defaults(fn=cmd_handshake)
    jn = sub.add_parser("join"); jn.add_argument("--code"); jn.add_argument("--name")
    jn.add_argument("--role", choices=["master", "slave"]); jn.add_argument("--master-name")
    jn.set_defaults(fn=cmd_join)
    po = sub.add_parser("poll"); po.set_defaults(fn=cmd_poll)
    cw = sub.add_parser("check-work"); cw.set_defaults(fn=cmd_check_work)
    stt = sub.add_parser("status"); stt.set_defaults(fn=cmd_status)
    dc = sub.add_parser("doctor"); dc.set_defaults(fn=cmd_doctor)
    dg = sub.add_parser("diagnose"); dg.set_defaults(fn=cmd_diagnose)
    w = sub.add_parser("watch"); w.add_argument("--interval", type=int, default=15,
        help="legacy; streaming makes polling interval unnecessary")
    w.set_defaults(fn=cmd_watch)
    args = ap.parse_args(); args.fn(args)

if __name__ == "__main__":
    main()
