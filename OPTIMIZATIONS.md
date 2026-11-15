# MuseBot optimisations (2026-11-16, master Vince)

Applied to `relay.py` in this folder. **Wire format, topic/key derivation,
envelope format, CLI commands and on-disk formats are unchanged**, so a
peer running the previous v6 build stays fully compatible — no forced
upgrade, no re-join, no new network code.

## What changed (internal only)

1. **Transport:** `http()` now retries transient failures (5xx/429,
   network/SSL) with exponential backoff + jitter, reads in chunks with
   a size cap. Stream reconnect uses exponential backoff instead of a
   fixed 5 s.
2. **Streams:** watcher streams each topic from the primary ntfy base
   only (was 4 streams: 2 topics × 2 bases); the mirror is polled every
   30 s as a fallback. Same messages, half the duplicate traffic.
3. **Caching:** `config()` / `load_peers()` / `load_state()` are cached
   in memory and re-read only when their files change; `save_state()`
   skips unchanged writes.
4. **Dedup window:** `processed_ids` / `acked_ids` cap raised 500 → 5000.
5. **Log rotation:** `messages.log.jsonl` rotates past 10 MB (keeps 3).
6. **File safety:** direct-file downloads capped at 50 MB, attachments
   at 5 MB, uncompressed zip at 100 MB; zip members that are symlinks,
   absolute paths or escape the destination are rejected.
7. **Bug fix:** `task_update` now says "by <own node name>" instead of
   the hardcoded "by Nicholas".
8. **Dead code removed:** v5 helpers (`derive_channel`, `handle_event`,
   `poll_peer`, `stream_peer`) and the non-network branches in
   `cmd_watch` / `cmd_poll`. This build is v6 network only.
9. **Dependencies pinned:** `cryptography==50.0.2` in `requirements.txt`
   + `requirements.lock`; `setup.sh` installs from the lock file.
10. **systemd:** `musebot.service` now uses the real path, `User=root`,
    `MemoryMax=512M`, start-limit and journal logging.
11. **check-work fast path:** if inbox/tasks/outbox have not changed
    since the last check and there are no pending dispatches, the full
    scan is skipped.
12. **Tests:** `tests/test_relay.py`, 15 tests (crypto round-trip,
    topic/key derivation, validate, state cap, HTTP retry/size cap,
    zip symlink rejection, task_update naming). Run:
    `python3 -m unittest discover -s tests -v` — 15/15 pass.

## Round 2 — transport hardening (2026-11-16, after the 01:28 sends got no ack)

Root cause found by `doctor`: both ntfy bases failed at the same time
with `SSL WRONG_VERSION_NUMBER` (1,462 occurrences in the log), while
curl to the same URLs returned 200 and a direct TLS probe got a plain
HTTP reply — the egress proxy intermittently breaks Python urllib's
TLS (its CONNECT returns a plain-HTTP error page). The channel flaps:
01:16–01:28 OK, 01:29–01:38 down, 01:39 one message through, then down
again. 小一's last heartbeat was 01:25:20; it is offline by the 12-min
rule as of 01:49, and the 4 messages sent at 01:28–01:39 (upgrade files,
upgrade task, name correction) are still unacked.

1. **`relay.py doctor`:** per base it tests DNS, TCP :443, direct TLS,
   raw-urllib GET /v1/health, curl GET /v1/health, and a publish+poll
   round-trip on a throwaway topic, plus peer presence, unacked
   messages and log counts. Verdict: `healthy` / `proxy_flaky`
   (urllib fails, curl works) / `bases_down`.
2. **curl fallback:** after urllib's retries are exhausted, `http()`
   retries once via the curl binary (list argv, no shell). Verified
   live: doctor's publish+poll succeeded through the fallback while
   urllib failed.
3. **Circuit breaker:** `transport/health.json` tracks per-base
   ok/fail/consecutive-fail; 3 consecutive failures opens the circuit
   for 5 minutes. Publish/poll/stream skip cooling-down bases when a
   healthy one exists, and probe again after the cooldown.
4. **Retry cap fix:** `resend_unacked` used to count only successful
   resends, so a permanently failing publish was retried every minute
   forever (tries stayed 0). Now every attempt counts, cap is 10,
   then the message is dead-lettered once in the log.
5. **Log throttling:** noisy transport events are logged at most once
   per key per 30 s (the SSL spam had reached 1,462 identical lines).
6. **Tests:** 8 more, total **23/23 pass** (health/circuit, curl
   fallback incl. a real local server, resend cap/dead-letter, doctor
   structure).

## Round 3 — curl as primary transport (2026-11-16)

`http()` now tries the curl binary first and falls back to urllib
(`MUSEBOT_TRANSPORT=urllib` forces the old path). Rationale: in a
10×10 test curl went 10/10 against ntfy while urllib went 9/10, and
during the outage curl succeeded while urllib failed. Streams still
use urllib (long-lived SSE), but they fall back to `poll_topic`,
which now goes through curl-primary `http()`. 3 more tests, total
**26/26 pass**.

Honest status after deploying round 3: curl-primary helps but does
**not** fully fix the peer traffic. At 02:00 the doctor topic
published+polled fine via curl, while peer-topic publish/poll in the
same minute failed in *both* curl (exit 35, SSL wrong version
number) and urllib. So the failure is per-connection through the
egress proxy, not per-client — the proxy intermittently returns a
plain-HTTP error on CONNECT, and which calls survive is luck of the
draw. The 4 upgrade messages to 小一 are at 5 resend tries each and
still unacked; 小一 has been offline since 01:25:20.

## How a peer upgrades (manual, not automatic)

There is **no auto-upgrade** in MuseBot: each node runs its own local
copy of `relay.py`. To upgrade a peer (e.g. 小一):

1. Send the new `relay.py` (+ `requirements.lock` if changed) to the
   peer owner, e.g. via the relay itself (`send-file` / `send-direct`).
2. The peer owner replaces their local copy, re-runs `./setup.sh`
   (only if dependencies changed), and restarts their watcher
   (`systemctl restart musebot.service` or `python3 relay.py watch`).
3. No re-join and no new network code are needed; the old and new
   builds interoperate on the same network.

Original unoptimised copy is kept as `relay.py.v6-orig` in this folder.
