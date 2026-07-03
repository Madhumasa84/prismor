import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime.scanner import discover_configs, parse_config


class TestScannerCodex(unittest.TestCase):
    def test_parse_codex_toml_mcp_servers(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = Path(tmpdir) / "config.toml"
            cfg.write_text(
                """
[mcp_servers.demo]
command = "node"
args = ["server.js"]
""".strip()
                + "\n",
                encoding="utf-8",
            )

            entries = parse_config(cfg)
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["name"], "demo")
            self.assertEqual(entries[0]["agent"], "unknown")
            self.assertEqual(entries[0]["config"]["command"], "node")

    def test_discover_project_codex_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            codex_dir = workspace / ".codex"
            codex_dir.mkdir()
            (codex_dir / "config.toml").write_text("[mcp_servers.demo]\ncommand='node'\n", encoding="utf-8")
            (codex_dir / "hooks.json").write_text('{"hooks":{}}' + "\n", encoding="utf-8")

            discovered = discover_configs(agent="codex", workspace=workspace)
            paths = {str(item["path"]) for item in discovered}
            self.assertIn(str(codex_dir / "config.toml"), paths)
            self.assertIn(str(codex_dir / "hooks.json"), paths)


if __name__ == "__main__":
    unittest.main()
