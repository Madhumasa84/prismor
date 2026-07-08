"""Regression tests for PrismorSec/prismor#131.

$PRISMOR_HOME is documented (prismor/runtime/paths.py, the cloaking README) as
a general override for Prismor's state directory. iam.py, canary.py, agents.py,
and several store.py helpers used to hardcode Path.home() instead, so setting
$PRISMOR_HOME had no effect on them — and store.py's own _secrets_dir()/
get_enrollment() disagreed with the (correctly $PRISMOR_HOME-aware) versions
used elsewhere, causing e.g. the dashboard and `prismor enroll-status` to be
able to report different enrollment state for the same device.
"""

import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestPrismorHomeHonored(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name)
        # PRISMOR_SECRETS_DIR is a more specific override than PRISMOR_HOME
        # and correctly takes priority when set — clear it so these tests
        # exercise the PRISMOR_HOME fallback tier regardless of the
        # environment they happen to run in.
        self._orig_env = {
            "PRISMOR_HOME": os.environ.get("PRISMOR_HOME"),
            "PRISMOR_SECRETS_DIR": os.environ.get("PRISMOR_SECRETS_DIR"),
        }
        os.environ["PRISMOR_HOME"] = str(self.home)
        os.environ.pop("PRISMOR_SECRETS_DIR", None)

    def tearDown(self):
        for key, value in self._orig_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self._tmp.cleanup()

    def test_store_prismor_home_reads_env_var(self):
        from prismor.runtime.store import prismor_home
        self.assertEqual(prismor_home(), self.home)

    def test_store_secrets_dir_falls_back_to_prismor_home(self):
        # This is the one that matters most: the session-store scrubbing
        # safety net must look at the same secrets dir cloak actually uses.
        import prismor.runtime.store as store_mod
        self.assertEqual(store_mod._secrets_dir(), self.home / "secrets")

    def test_runtime_workspace_state_lives_under_prismor_home(self):
        import prismor.runtime.store as store_mod

        workspace = self.home.parent / f"demo-workspace-{id(self)}"
        workspace.mkdir()

        data_dir = store_mod.get_data_dir(workspace)

        self.assertEqual(data_dir, self.home)
        self.assertEqual(store_mod.get_db_path(workspace), data_dir / "prismor.db")
        self.assertEqual(store_mod.get_sessions_dir(workspace), data_dir / "sessions")
        self.assertFalse(str(data_dir).startswith(str(workspace / ".prismor")))

    def test_iam_global_path_honors_prismor_home(self):
        import prismor.runtime.iam as iam_mod
        self.assertEqual(iam_mod._global_iam_path(), self.home / "iam.yaml")

    def test_canary_registry_honors_prismor_home(self):
        import prismor.runtime.canary as canary_mod
        self.assertEqual(canary_mod._canary_registry_path(), self.home / "canaries.json")

    def test_agents_global_path_honors_prismor_home(self):
        import prismor.runtime.agents as agents_mod
        self.assertEqual(agents_mod._global_agents_path(), self.home / "agents.yaml")

    def test_get_enrollment_agrees_with_enterprise_identity(self):
        import json
        identity = {
            "schema": "prismor.identity.v1",
            "device_id": "test-device",
            "org_id": "test-org",
            "device_key": "fake-key-not-real",
            "org_name": "Test Org",
            "label": "test",
            "api_base": "https://example.invalid",
        }
        (self.home / "identity.json").write_text(json.dumps(identity), encoding="utf-8")

        from prismor.runtime.store import get_enrollment
        from prismor.runtime.enterprise.identity import load_identity

        store_result = get_enrollment()
        enterprise_result = load_identity()
        self.assertIsNotNone(store_result)
        self.assertIsNotNone(enterprise_result)
        self.assertEqual(store_result["device_id"], enterprise_result["device_id"])
        self.assertEqual(store_result["org_id"], enterprise_result["org_id"])


if __name__ == "__main__":
    unittest.main()
