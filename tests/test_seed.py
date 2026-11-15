"""Drive the shipped feed seeder, the viewer, and the admin mask."""

import io
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import app as kitten  # noqa: E402


CAMERA_URL = "rtsp://camuser:s3cret-test@10.0.20.40:554/stream1"


class SeedFeedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        kitten.app.config.update(
            TESTING=True,
            SECRET_KEY="test-secret",
            ADMIN_PASSWORD="test-admin-password",
            DB_PATH=os.path.join(self.tmp.name, "feeds.db"),
            HLS_ROOT=os.path.join(self.tmp.name, "hls"),
            KITTEN_UPLOAD_ROOT=os.path.join(self.tmp.name, "kittens"),
        )
        self.client = kitten.app.test_client()
        self._old_url = os.environ.get("SEED_RTSP_URL")
        self._old_name = os.environ.get("SEED_FEED_NAME")

    def tearDown(self):
        with kitten.app.app_context():
            db = kitten.g.pop("db", None)
            if db is not None:
                db.close()
        if self._old_url is None:
            os.environ.pop("SEED_RTSP_URL", None)
        else:
            os.environ["SEED_RTSP_URL"] = self._old_url
        if self._old_name is None:
            os.environ.pop("SEED_FEED_NAME", None)
        else:
            os.environ["SEED_FEED_NAME"] = self._old_name
        self.tmp.cleanup()

    def _seed(self, url=CAMERA_URL, name="Kitten Cam"):
        os.environ["SEED_RTSP_URL"] = url
        os.environ["SEED_FEED_NAME"] = name
        with kitten.app.app_context():
            kitten.init_db()
            return kitten.seed_feed_from_env()

    def test_empty_database_gets_one_camera_and_pages_hide_the_password(self):
        self.assertTrue(self._seed())
        with kitten.app.app_context():
            self.assertFalse(kitten.seed_feed_from_env())
            rows = kitten.get_db().execute("SELECT name, rtsp_url FROM feeds").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "Kitten Cam")
        parsed = urlparse(rows[0]["rtsp_url"])
        self.assertEqual(parsed.hostname, "10.0.20.40")
        self.assertEqual(parsed.port, 554)
        self.assertEqual(parsed.path, "/stream1")
        masked = kitten.mask_rtsp_url(rows[0]["rtsp_url"])
        self.assertNotIn("s3cret-test", masked)
        self.assertIn("***", masked)

        viewer = self.client.get("/")
        viewer_body = viewer.get_data(as_text=True)
        self.assertEqual(viewer.status_code, 200)
        self.assertIn("Kitten Cam", viewer_body)
        self.assertIn("/hls/feed-", viewer_body)
        self.assertIn("data-feed-src", viewer_body)
        self.assertIn("15 * 60 * 1000", viewer_body)
        self.assertIn("liveDurationInfinity", viewer_body)
        self.assertNotIn("s3cret-test", viewer_body)
        self.assertNotIn(CAMERA_URL, viewer_body)

        with self.client.session_transaction() as sess:
            sess["admin_logged_in"] = True
        admin = self.client.get("/admin")
        admin_body = admin.get_data(as_text=True)
        self.assertEqual(admin.status_code, 200)
        self.assertNotIn("s3cret-test", admin_body)
        self.assertIn("camuser:***", admin_body)

    def test_existing_feed_is_not_replaced(self):
        self.assertTrue(self._seed())
        os.environ["SEED_RTSP_URL"] = "rtsp://other:different-secret@10.9.9.9:554/other"
        with kitten.app.app_context():
            self.assertFalse(kitten.seed_feed_from_env())
            row = kitten.get_db().execute("SELECT rtsp_url FROM feeds").fetchone()
        self.assertEqual(urlparse(row["rtsp_url"]).hostname, "10.0.20.40")

    def test_blank_or_non_rtsp_url_does_not_insert(self):
        os.environ["SEED_RTSP_URL"] = ""
        with kitten.app.app_context():
            kitten.init_db()
            self.assertFalse(kitten.seed_feed_from_env())
        os.environ["SEED_RTSP_URL"] = "http://10.0.20.40/stream1"
        with kitten.app.app_context():
            self.assertFalse(kitten.seed_feed_from_env())
            total = kitten.get_db().execute("SELECT COUNT(*) AS total FROM feeds").fetchone()["total"]
        self.assertEqual(total, 0)

    def test_swarm_stack_does_not_publish_host_http_ports(self):
        text = (ROOT / "docker-stack.yml").read_text(encoding="utf-8")
        self.assertIn("replicas: 1", text)
        self.assertIn("ca_public", text)
        self.assertIn("kittens.cyberask.co.uk", text)
        self.assertNotIn("80:80", text)
        self.assertNotIn("443:443", text)
        self.assertNotIn("published:", text)
        self.assertIn("${KITTEN_SWARM_NODE}", text)
        self.assertIn("${KITTEN_WEB_IMAGE}", text)
        self.assertIn("${SEED_RTSP_URL}", text)
        nginx_conf = (ROOT / "nginx" / "default.conf").read_text(encoding="utf-8")
        self.assertIn("kittens_web:8000", nginx_conf)
        self.assertNotIn("http://web:8000", nginx_conf)
        self.assertIn("kitten_nginx_conf_v2", text)

    def test_ffmpeg_stderr_masks_the_rtsp_password(self):
        self._seed()
        raw = b"Error opening input file rtsp://camuser:s3cret-test@10.0.20.40:554/stream1\n"

        class FakeProc:
            def __init__(self, *args, **kwargs):
                self.kwargs = kwargs
                if kwargs.get("stderr") is subprocess.PIPE:
                    self.stderr = io.BytesIO(raw)
                else:
                    self.stderr = None

            def poll(self):
                return None

            def terminate(self):
                return None

            def wait(self, timeout=None):
                return 0

            def kill(self):
                return None

        with patch("app.subprocess.Popen", FakeProc):
            with kitten.app.app_context():
                with self.assertLogs(kitten.app.logger, level="WARNING") as captured:
                    self.assertTrue(kitten.start_stream(1, CAMERA_URL))
                    time.sleep(0.4)
                    kitten.stop_stream(1)
        joined = "\n".join(captured.output)
        self.assertNotIn("s3cret-test", joined)
        self.assertIn("camuser:***@", joined)
        self.assertIn("10.0.20.40", joined)

    def test_restart_clears_cached_segments_and_opens_the_camera_again(self):
        self._seed()
        playlist = Path(kitten.app.config["HLS_ROOT"]) / "feed-1"
        playlist.mkdir(parents=True)
        (playlist / "seg_00000.ts").write_bytes(b"stale-cache")
        (playlist / "index.m3u8").write_text("#EXTM3U\n", encoding="utf-8")

        class FakeProc:
            def __init__(self, *args, **kwargs):
                self.stderr = io.BytesIO(b"")

            def poll(self):
                return None

            def terminate(self):
                return None

            def wait(self, timeout=None):
                return 0

            def kill(self):
                return None

        with patch("app.subprocess.Popen", FakeProc):
            with kitten.app.app_context():
                self.assertEqual(kitten.restart_all_streams(), 1)
                self.assertFalse((playlist / "seg_00000.ts").exists())
                self.assertIn(1, kitten.STREAM_PROCESSES)
                kitten.stop_stream(1)

    def test_restart_timer_fires_once_and_can_be_disabled(self):
        kitten.app.config["STREAM_RESTART_SECONDS"] = 0
        with patch.object(kitten, "restart_all_streams") as restart:
            kitten.stream_restart_loop(threading.Event())
        restart.assert_not_called()

        kitten.app.config["STREAM_RESTART_SECONDS"] = 0.01
        stop = threading.Event()

        def stop_after_reconnect():
            stop.set()

        with patch.object(kitten, "restart_all_streams", side_effect=stop_after_reconnect) as restart:
            kitten.stream_restart_loop(stop)
        restart.assert_called_once()
        kitten.app.config["STREAM_RESTART_SECONDS"] = 900
