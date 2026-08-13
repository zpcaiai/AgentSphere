from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import threading
import unittest

from python.platform_sre.http_load_gate import LoadGateError, run_load_gate


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format, *args):
        del format, args


class HttpLoadGateTests(unittest.TestCase):
    def test_real_local_http_concurrency_is_measured(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            report = run_load_gate(
                f"http://127.0.0.1:{server.server_port}/healthz",
                40, 8, 200, 1.0, 2000, allow_http_local=True,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertTrue(report["passed"])
        self.assertEqual(report["status_counts"], {"200": 40})
        self.assertEqual(report["method"], "GET")
        self.assertFalse(report["production_evidence"])

    def test_plain_http_non_local_target_is_denied(self):
        with self.assertRaises(LoadGateError):
            run_load_gate("http://example.test/", 1, 1, 200, 1.0, 1000, allow_http_local=True)
        with self.assertRaises(LoadGateError):
            run_load_gate(
                "http://127.0.0.1:8080/", 1, 1, 200, 1.0, 1000,
                allow_http_local=True, headers={"Authorization": "secret"},
            )

    def test_sustained_pacing_and_secret_header_environment(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        os.environ["AGENTTRUST_TEST_LOAD_AUTH"] = "Bearer opaque-test-value"
        try:
            report = run_load_gate(
                f"http://127.0.0.1:{server.server_port}/healthz",
                8, 2, 200, 1.0, 2000, allow_http_local=True,
                header_environments={"Authorization": "AGENTTRUST_TEST_LOAD_AUTH"},
                duration_seconds=1,
            )
        finally:
            os.environ.pop("AGENTTRUST_TEST_LOAD_AUTH", None)
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertTrue(report["passed"])
        self.assertTrue(report["sustained_duration_met"])
        self.assertEqual(report["secret_header_names"], ["authorization"])


if __name__ == "__main__":
    unittest.main()
