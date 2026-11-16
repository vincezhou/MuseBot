#!/usr/bin/env python3
"""Unit tests for MuseBot relay.py (optimised v6).

Run:  python3 -m unittest discover -s tests -v
These tests import relay.py from the repo root and re-point its
file-based globals at a temp dir, so the real ~/workspace/musebot
config/state are never touched.
"""
import base64
import hashlib
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "vendor"))
import relay  # noqa: E402

CODE = "MB-TEST-CODE-1234"


def _good_msg(peer, **over):
    msg = {
        "relay_version": 2, "pairing_code": CODE, "id": "msg-0123456789abcdef",
        "from": "Vince", "to": "小一", "type": "message",
        "created_at": relay.now_iso(), "body": "hi", "owner_approved": True,
    }
    msg.update(over)
    return msg


class BaseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        # Re-point relay's file globals at the temp dir.
        self._orig = {k: getattr(relay, k) for k in
                      ("BASE", "INBOX", "OUTBOX", "PROCESSED", "TO_PEER", "FROM_PEER",
                       "FILES_TO_PEER", "FILES_FROM_PEER", "FILES_RECEIVED", "FILES_SENT",
                       "TASKS_IN", "PENDING", "STATE_F", "PRESENCE_F", "PEERS_F",
                       "DIRECT_SENT_F", "LOG", "HEALTH_F")}
        relay.BASE = self.tmp
        relay.INBOX = self.tmp / "inbox"
        relay.OUTBOX = self.tmp / "outbox"
        relay.PROCESSED = self.tmp / "processed"
        relay.TO_PEER = self.tmp / "transport" / "to_peer"
        relay.FROM_PEER = self.tmp / "transport" / "from_peer"
        relay.FILES_TO_PEER = self.tmp / "transport" / "files_to_peer"
        relay.FILES_FROM_PEER = self.tmp / "transport" / "files_from_peer"
        relay.FILES_RECEIVED = self.tmp / "files" / "received"
        relay.FILES_SENT = self.tmp / "files" / "sent"
        relay.TASKS_IN = self.tmp / "tasks" / "incoming"
        relay.PENDING = self.tmp / "transport" / "pending"
        relay.STATE_F = self.tmp / "transport" / "state.json"
        relay.PRESENCE_F = self.tmp / "presence.json"
        relay.PEERS_F = self.tmp / "peers.json"
        relay.DIRECT_SENT_F = self.tmp / "files" / "direct_sent.json"
        relay.LOG = self.tmp / "messages.log.jsonl"
        relay.HEALTH_F = self.tmp / "transport" / "health.json"
        relay.OUTGOING_F = self.tmp / "tasks" / "outgoing.json"
        relay._CONFIG_CACHE.update({"mtime": None, "data": {
            "network_code": CODE,
            "self": {"node_name": "Vince", "role": "master", "master_name": "Vince"},
            "task_policy": {"mode": "auto_execute"},
            "relay_id": "musebot-01"}})
        relay._PEERS_CACHE.update({"mtime": None, "data": None})
        relay._STATE_CACHE.update({"data": None, "written": None})
        (self.tmp / "config.json").write_text(json.dumps(relay._CONFIG_CACHE["data"]))
        (self.tmp / "transport").mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        for k, v in self._orig.items():
            setattr(relay, k, v)
        relay._CONFIG_CACHE.update({"mtime": None, "data": {}})
        relay._PEERS_CACHE.update({"mtime": None, "data": None})
        relay._STATE_CACHE.update({"data": None, "written": None})

    def peer(self):
        return relay.node_peer("小一", "slave")


class TestCrypto(BaseTest):
    def test_topic_derivation_is_deterministic(self):
        self.assertEqual(relay.announce_topic(CODE), relay.announce_topic(CODE))
        self.assertEqual(relay.node_topic(CODE, "小一"), relay.node_topic(CODE, "小一"))
        self.assertNotEqual(relay.node_topic(CODE, "小一"), relay.node_topic(CODE, "Vince"))
        self.assertTrue(relay.announce_topic(CODE).startswith("musebot-"))

    def test_pair_key_is_directional(self):
        self.assertNotEqual(relay.pair_key(CODE, "Vince", "小一"),
                            relay.pair_key(CODE, "小一", "Vince"))

    def test_wrap_unwrap_roundtrip(self):
        peer = self.peer()
        # A message FROM 小一 TO Vince, unwrapped by Vince (self_name).
        msg = _good_msg(peer, **{"from": "小一", "to": "Vince"})
        wrapped = relay.wrap_envelope(msg, peer)
        self.assertTrue(wrapped.get("encrypted"))
        self.assertEqual(relay.unwrap_envelope(wrapped, peer), msg)

    def test_unwrap_rejects_wrong_code(self):
        peer = self.peer()
        wrapped = relay.wrap_envelope(_good_msg(peer), peer)
        with mock.patch.object(relay, "network_code", return_value="MB-OTHER-CODE-9999"):
            with self.assertRaises(Exception):
                relay.unwrap_envelope(wrapped, peer)


class TestValidate(BaseTest):
    def test_accepts_good_message(self):
        self.assertIsNone(relay.validate(_good_msg(self.peer()), self.peer()))

    def test_rejects_bad_pairing_code(self):
        self.assertIn("pairing_code", relay.validate(
            _good_msg(self.peer(), pairing_code="WRONG"), self.peer()))

    def test_rejects_old_message(self):
        self.assertIn("too old", relay.validate(
            _good_msg(self.peer(), created_at="2020-01-01T00:00:00+00:00"), self.peer()))

    def test_rejects_task_without_details(self):
        self.assertIsNotNone(relay.validate(
            _good_msg(self.peer(), type="task_request", task={"title": "x"}), self.peer()))


class TestState(BaseTest):
    def test_save_state_caps_at_5000_not_500(self):
        s = {"processed_ids": [f"msg-{i}" for i in range(6000)],
             "acked_ids": [], "attempts": {}, "last_event": {}}
        relay.save_state(s)
        saved = json.loads(relay.STATE_F.read_text())
        self.assertEqual(len(saved["processed_ids"]), 5000)

    def test_save_state_skips_unchanged_write(self):
        s = {"processed_ids": ["msg-1"], "acked_ids": [], "attempts": {}, "last_event": {}}
        relay.save_state(s)
        mtime1 = relay.STATE_F.stat().st_mtime_ns
        relay.save_state(dict(s))
        self.assertEqual(mtime1, relay.STATE_F.stat().st_mtime_ns)


class TestHttpRetry(BaseTest):
    def test_retries_transient_then_succeeds(self):
        calls = {"n": 0}

        class Resp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self, n=-1): return b"ok"

        def fake_urlopen(req, timeout=30):
            calls["n"] += 1
            if calls["n"] < 3:
                raise ConnectionError("boom")
            return Resp()

        with mock.patch.object(relay.urllib.request, "urlopen", fake_urlopen), \
             mock.patch.object(relay.time, "sleep", lambda s: None):
            self.assertEqual(relay.http("GET", "https://example.invalid/x"), b"ok")
        self.assertEqual(calls["n"], 3)

    def test_max_bytes_enforced(self):
        class Resp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self, n=-1): return b"x" * 100

        with mock.patch.object(relay.urllib.request, "urlopen", lambda *a, **k: Resp()):
            with self.assertRaises(ValueError):
                relay.http("GET", "https://example.invalid/x", max_bytes=10, retries=0)


class TestZipSafety(BaseTest):
    def _direct_file_msg(self, zip_bytes):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key = AESGCM.generate_key(bit_length=256)
        nonce, ct = relay.aes_encrypt(key, zip_bytes)
        blob = nonce + ct
        return {
            "relay_version": 2, "pairing_code": CODE, "id": "msg-direct1",
            "from": "小一", "to": "Vince", "type": "file",
            "created_at": relay.now_iso(), "body": "file", "owner_approved": True,
            "direct_file": {
                "url": "https://example.invalid/payload.enc", "name": "payload.zip",
                "archive": "zip", "key": base64.b64encode(key).decode(),
                "blob_sha256": hashlib.sha256(blob).hexdigest(),
                "zip_sha256": hashlib.sha256(zip_bytes).hexdigest(),
                "zip_size": len(zip_bytes)}}, blob

    def test_symlink_in_zip_is_rejected(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            info = zipfile.ZipInfo("evil-link")
            info.external_attr = (0o120777 << 16)  # symlink
            z.writestr(info, "/etc/passwd")
            z.writestr("ok.txt", "hello")
        msg, blob = self._direct_file_msg(buf.getvalue())
        with mock.patch.object(relay, "http", return_value=blob):
            err = relay.process_direct_file(msg, self.peer())
        self.assertIsNotNone(err)
        self.assertIn("unsafe", err)

    def test_clean_zip_is_accepted(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("ok.txt", "hello")
        msg, blob = self._direct_file_msg(buf.getvalue())
        with mock.patch.object(relay, "http", return_value=blob):
            err = relay.process_direct_file(msg, self.peer())
        self.assertIsNone(err)
        self.assertEqual((relay.FILES_RECEIVED / "msg-direct1" / "ok.txt").read_text(), "hello")


class TestTaskUpdate(BaseTest):
    def test_task_update_names_self_not_nicholas(self):
        relay.TASKS_IN.mkdir(parents=True, exist_ok=True)
        rec = {"message_id": "msg-task1", "peer_id": self.peer()["peer_id"],
               "status": "pending_owner_approval", "from": "小一",
               "task": {"title": "Do a thing", "details": "details"}}
        (relay.TASKS_IN / "msg-task1.json").write_text(json.dumps(rec))
        relay.PEERS_F.write_text(json.dumps({"peers": [self.peer()]}))
        relay._PEERS_CACHE.update({"mtime": None, "data": None})
        args = mock.Mock()
        args.message_id = "msg-task1"
        with mock.patch.object(relay, "transport_publish_envelope", return_value=True):
            relay.set_task_status(args, "approved")
        out = list(relay.OUTBOX.glob("*.json"))
        self.assertEqual(len(out), 1)
        body = json.loads(out[0].read_text())["body"]
        self.assertIn("by Vince", body)
        self.assertNotIn("Nicholas", body)


if __name__ == "__main__":
    unittest.main()


class TestHealth(BaseTest):
    def test_three_failures_open_circuit(self):
        base = "https://ntfy.envs.net"
        for _ in range(3):
            relay.record_transport_failure(base, "boom")
        rec = relay.load_health()[base]
        self.assertEqual(rec["consecutive_fail"], 3)
        self.assertGreater(rec["unhealthy_until"], relay.now_ts())
        self.assertFalse(relay.base_healthy(base))

    def test_success_closes_circuit(self):
        base = "https://ntfy.envs.net"
        for _ in range(3):
            relay.record_transport_failure(base, "boom")
        relay.record_transport_success(base)
        self.assertTrue(relay.base_healthy(base))
        self.assertEqual(relay.load_health()[base]["consecutive_fail"], 0)

    def test_ordered_bases_puts_healthy_first(self):
        peer = self.peer()
        peer["base_url"] = "https://ntfy.envs.net"
        peer["mirror_base_url"] = "https://ntfy.adminforge.de"
        for _ in range(3):
            relay.record_transport_failure("https://ntfy.envs.net", "boom")
        self.assertEqual(relay.ordered_bases(peer)[0], "https://ntfy.adminforge.de")


class TestCurlFallback(BaseTest):
    def test_http_falls_back_to_curl_after_urllib_fails(self):
        with mock.patch.object(relay.urllib.request, "urlopen",
                               side_effect=__import__("ssl").SSLError("WRONG_VERSION_NUMBER")), \
             mock.patch.object(relay, "_http_via_curl", return_value=b"via-curl") as curl_mock, \
             mock.patch.object(relay.time, "sleep", lambda s: None):
            self.assertEqual(relay.http("GET", "https://example.invalid/x", retries=1), b"via-curl")
        curl_mock.assert_called_once()

    def test_http_via_curl_real_local_server(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"hello-doctor")
            def log_message(self, *a):
                pass
        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        import threading
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            body = relay._http_via_curl("GET", f"http://127.0.0.1:{srv.server_address[1]}/x", timeout=10)
            self.assertEqual(body, b"hello-doctor")
        finally:
            srv.shutdown()


class TestResendCap(BaseTest):
    def _outbox_msg(self):
        relay.OUTBOX.mkdir(parents=True, exist_ok=True)
        relay.PEERS_F.write_text(json.dumps({"peers": [self.peer()]}))
        relay._PEERS_CACHE.update({"mtime": None, "data": None})
        msg = {"id": "msg-cap1", "type": "message", "peer_id": self.peer()["peer_id"],
               "created_at": relay.now_iso(), "body": "hi"}
        (relay.OUTBOX / "msg-cap1.json").write_text(json.dumps(msg))
        return msg

    def test_failed_resend_counts_toward_cap(self):
        self._outbox_msg()
        with mock.patch.object(relay, "transport_publish_envelope", return_value=False):
            relay.resend_unacked()
        s = relay.load_state()
        self.assertEqual(s["attempts"]["msg-cap1"]["count"], 1)

    def test_past_cap_is_dead_lettered_once(self):
        self._outbox_msg()
        relay.save_state({"processed_ids": [], "acked_ids": [], "attempts": {"msg-cap1": {"count": 10, "last": 0}}, "last_event": {}})
        with mock.patch.object(relay, "transport_publish_envelope") as pub:
            relay.resend_unacked()
        pub.assert_not_called()
        self.assertIn("dead_letter", relay.LOG.read_text())
        self.assertTrue(relay.load_state()["attempts"]["msg-cap1"]["dead_logged"])


class TestDoctor(BaseTest):
    def test_doctor_runs_and_reports_structure(self):
        import io as _io, contextlib
        buf = _io.StringIO()
        with contextlib.redirect_stdout(buf):
            relay.cmd_doctor(mock.Mock())
        report = json.loads(buf.getvalue())
        self.assertIn(report["verdict"], {"healthy", "proxy_flaky", "bases_down"})
        self.assertEqual(set(report["bases"]), {"https://ntfy.envs.net", "https://ntfy.adminforge.de"})
        for base, res in report["bases"].items():
            for key in ("dns", "tcp443", "tls_direct", "urllib_health", "curl_health", "publish_poll"):
                self.assertIn(key, res)
        self.assertIn("unacked", report)
        self.assertIn("log", report)


class TestCurlPrimary(BaseTest):
    def test_http_uses_curl_first_and_skips_urllib(self):
        with mock.patch.object(relay, "_http_via_curl", return_value=b"via-curl-primary") as curl_mock, \
             mock.patch.object(relay.urllib.request, "urlopen", side_effect=AssertionError("urllib must not be called")):
            self.assertEqual(relay.http("GET", "https://example.invalid/x"), b"via-curl-primary")
        curl_mock.assert_called_once()

    def test_http_falls_back_to_urllib_when_curl_fails(self):
        class Resp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self, n=-1): return b"via-urllib"
        with mock.patch.object(relay, "_http_via_curl", side_effect=ConnectionError("curl down")), \
             mock.patch.object(relay.urllib.request, "urlopen", lambda *a, **k: Resp()):
            self.assertEqual(relay.http("GET", "https://example.invalid/x"), b"via-urllib")

    def test_urllib_primary_env_skips_curl(self):
        class Resp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self, n=-1): return b"via-urllib"
        with mock.patch.object(relay, "TRANSPORT_PRIMARY", "urllib"), \
             mock.patch.object(relay, "_http_via_curl", side_effect=AssertionError("curl must not be called")), \
             mock.patch.object(relay.urllib.request, "urlopen", lambda *a, **k: Resp()):
            self.assertEqual(relay.http("GET", "https://example.invalid/x"), b"via-urllib")


class TestLiveness(BaseTest):
    def setUp(self):
        super().setUp()
        self.live = self.tmp / "liveness.jsonl"
        self.lstate = self.tmp / "transport" / "liveness_state.json"
        self._live_patch = mock.patch.object(relay, "LIVENESS_F", self.live)
        self._state_patch = mock.patch.object(relay, "LIVENESS_STATE_F", self.lstate)
        self._live_patch.start()
        self._state_patch.start()

    def tearDown(self):
        self._live_patch.stop()
        self._state_patch.stop()
        super().tearDown()

    def test_classify_startup(self):
        info = {"boot_id": "boot-A", "machine_id": "m-1"}
        self.assertEqual(relay.classify_startup({}, info, None), "first_start")
        self.assertEqual(relay.classify_startup({"boot_id": "boot-A"}, info, 30), "clean_restart")
        self.assertEqual(relay.classify_startup({"boot_id": "boot-A"}, info, 600), "process_down")
        self.assertEqual(relay.classify_startup({"boot_id": "boot-B"}, info, 600),
                         "machine_reboot_or_replace")

    def test_classify_gap(self):
        a = {"ts": "2026-11-16T01:00:00+08:00", "event": "tick", "boot_id": "boot-A"}
        b = {"ts": "2026-11-16T01:01:00+08:00", "event": "tick", "boot_id": "boot-A"}
        self.assertIsNone(relay.classify_gap(a, b))
        c = {"ts": "2026-11-16T01:30:00+08:00", "event": "tick", "boot_id": "boot-A"}
        g = relay.classify_gap(a, c)
        self.assertEqual(g["cause"], "process_down")
        self.assertEqual(g["gap_s"], 1800)
        d = {"ts": "2026-11-16T01:30:00+08:00", "event": "tick", "boot_id": "boot-B"}
        self.assertEqual(relay.classify_gap(a, d)["cause"], "machine_reboot_or_replace")
        e = {"ts": "2026-11-16T01:30:00+08:00", "event": "startup",
             "verdict": "machine_reboot_or_replace", "machine_id_changed": True}
        g2 = relay.classify_gap(a, e)
        self.assertEqual(g2["cause"], "machine_reboot_or_replace")
        self.assertTrue(g2["machine_id_changed"])

    def test_startup_then_tick_then_reboot_verdict(self):
        info_a = {"boot_id": "boot-A", "machine_id": "m-1", "hostname": "h",
                  "uptime_s": 100.0, "pid": 1, "python": "3.12", "curl": True, "proxy_env": True}
        with mock.patch.object(relay, "machine_info", return_value=info_a):
            first = relay.record_startup()
        self.assertEqual(first["verdict"], "first_start")
        with mock.patch.object(relay, "machine_info", return_value=info_a):
            relay.record_liveness_tick()
        lines = self.live.read_text().strip().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[1])["event"], "tick")
        self.assertIsInstance(json.loads(lines[1])["rss_mb"], int)
        self.assertGreater(json.loads(lines[1])["rss_mb"], 0)
        # Simulate a reboot: new boot id, long gap since the tick.
        state = json.loads(self.lstate.read_text())
        state["last_tick_ts"] = relay.now_ts() - 3600
        self.lstate.write_text(json.dumps(state))
        info_b = dict(info_a, boot_id="boot-B", machine_id="m-2")
        with mock.patch.object(relay, "machine_info", return_value=info_b):
            second = relay.record_startup()
        self.assertEqual(second["verdict"], "machine_reboot_or_replace")
        self.assertTrue(second["machine_id_changed"])

    def test_diagnose_reports_gap(self):
        self.live.write_text(
            '{"ts": "2026-11-16T01:00:00+08:00", "event": "tick", "boot_id": "boot-A"}\n'
            '{"ts": "2026-11-16T01:30:00+08:00", "event": "tick", "boot_id": "boot-A"}\n')
        buf = io.StringIO()
        with mock.patch.object(sys, "stdout", buf):
            relay.cmd_diagnose(None)
        report = json.loads(buf.getvalue())
        self.assertEqual(len(report["downtime_gaps"]), 1)
        self.assertEqual(report["downtime_gaps"][0]["cause"], "process_down")
        self.assertEqual(report["total_downtime_s"], 1800)
