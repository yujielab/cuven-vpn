import contextlib
import importlib.util
import io
from ipaddress import ip_address
from pathlib import Path
import ssl
import unittest


path = Path(__file__).resolve().parents[2] / "deploy/check-egress.py"
spec = importlib.util.spec_from_file_location("check_egress", path)
egress = importlib.util.module_from_spec(spec)
spec.loader.exec_module(egress)


class CheckEgressPrivacyTests(unittest.TestCase):
    def report(self, failure):
        output = io.StringIO()
        with egress.CheckServer(ip_address("127.0.0.1"), 0, None, set(), "/test") as server:
            with contextlib.redirect_stderr(output):
                try:
                    raise failure
                except Exception:
                    server.handle_error(None, ("192.0.2.10", 53000))
        return output.getvalue()

    def test_interrupted_requests_do_not_log_the_peer(self):
        for failure in (ConnectionResetError(), BrokenPipeError(), TimeoutError(), ssl.SSLError()):
            with self.subTest(failure=type(failure).__name__):
                self.assertEqual(self.report(failure), "")

    def test_unexpected_failure_reports_only_its_type(self):
        self.assertEqual(
            self.report(RuntimeError("request at /private-test-path")),
            "Egress check request failed (RuntimeError).\n",
        )


if __name__ == "__main__":
    unittest.main()
