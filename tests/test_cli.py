import argparse
import os
import tempfile
import unittest
from vaultguard.cli import handle_purge, handle_remediate, handle_scan
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.sample_dir = os.path.join(_ROOT, "examples", "sample_repo")

    def test_cli_scan(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f_json:
            out_json = f_json.name
        with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as f_html:
            out_html = f_html.name

        try:
            args = argparse.Namespace(
                path=self.sample_dir,
                verify=False,
                simulate=True,
                output_json=out_json,
                output_html=out_html,
                fail_on_active=False,
                fail_on_severity=None,
            )
            code = handle_scan(args)
            self.assertEqual(code, 0)
            self.assertTrue(os.path.isfile(out_json))
            self.assertTrue(os.path.isfile(out_html))
        finally:
            for p in (out_json, out_html):
                if os.path.exists(p):
                    os.remove(p)

    def test_cli_purge(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".sh") as f_sh:
            out_sh = f_sh.name

        try:
            args = argparse.Namespace(
                path=self.sample_dir,
                output=out_sh,
            )
            code = handle_purge(args)
            self.assertEqual(code, 0)
            self.assertTrue(os.path.isfile(out_sh))
        finally:
            if os.path.exists(out_sh):
                os.remove(out_sh)

    def test_cli_remediate(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".env.example") as f_env:
            out_env = f_env.name

        try:
            args = argparse.Namespace(
                path=self.sample_dir,
                output_env=out_env,
            )
            code = handle_remediate(args)
            self.assertEqual(code, 0)
            self.assertTrue(os.path.isfile(out_env))
        finally:
            if os.path.exists(out_env):
                os.remove(out_env)


if __name__ == "__main__":
    unittest.main()
