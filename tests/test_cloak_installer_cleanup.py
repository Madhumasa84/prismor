from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from prismor.runtime.cloaking import install, status, uninstall


class TestCloakInstallerCleanup(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmp.name)
        self.settings = self.workspace / ".claude" / "settings.json"
        self.settings.parent.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self._tmp.cleanup()

    def test_install_replaces_legacy_warden_hooks_in_place(self):
        self.settings.write_text(json.dumps({
            "hooks": {
                "UserPromptSubmit": [{
                    "hooks": [{
                        "type": "command",
                        "command": "/tmp/site-packages/warden/cloaking/hooks/userprompt-guard.sh",
                    }]
                }],
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [{
                        "type": "command",
                        "command": "/tmp/site-packages/warden/cloaking/hooks/decloak.sh",
                    }]
                }],
                "PostToolUse": [{
                    "matcher": "mcp__.*",
                    "hooks": [{
                        "type": "command",
                        "command": "/tmp/site-packages/warden/cloaking/hooks/recloak-mcp.sh",
                    }]
                }],
            }
        }), encoding="utf-8")

        install(workspace=self.workspace, scope="project")
        data = json.loads(self.settings.read_text(encoding="utf-8"))
        serialized = json.dumps(data)

        self.assertNotIn("site-packages/warden/cloaking/hooks", serialized)
        self.assertIn("prismor/runtime/cloaking/hooks/userprompt-guard.sh", serialized)
        self.assertIn("prismor/runtime/cloaking/hooks/decloak.sh", serialized)
        self.assertIn("prismor/runtime/cloaking/hooks/recloak-mcp.sh", serialized)

    def test_status_and_uninstall_recognize_legacy_warden_hooks(self):
        self.settings.write_text(json.dumps({
            "hooks": {
                "UserPromptSubmit": [{
                    "hooks": [{
                        "type": "command",
                        "command": "/tmp/site-packages/warden/cloaking/hooks/userprompt-guard.sh",
                    }]
                }]
            },
            "env": {"PRISMOR_SECRETS_DIR": "/tmp/secrets"},
        }), encoding="utf-8")

        st = status(workspace=self.workspace, scope="project")
        self.assertTrue(st["installed"])
        self.assertIn("UserPromptSubmit", st["events"][0])

        result = uninstall(workspace=self.workspace, scope="project")
        self.assertTrue(result["removed"])

        data = json.loads(self.settings.read_text(encoding="utf-8"))
        self.assertEqual(data.get("hooks"), {})
        self.assertNotIn("env", data)


if __name__ == "__main__":
    unittest.main()
