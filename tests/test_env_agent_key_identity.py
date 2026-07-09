"""$PRISMOR_AGENT_KEY — the deviceless (SDK/deployed) identity path.

A deployed agent has no machine to enroll, so an org admin mints an agent key
in the console and wires it into the deployment as $PRISMOR_AGENT_KEY. The
runtime must treat it as a full identity (device_key bearer credential), let
it take precedence over any baked-in identity.json, and never persist it.
"""
import json
import os
import tempfile
import unittest
from pathlib import Path

from prismor.runtime.enterprise import identity as _identity


class TestEnvAgentKeyIdentity(unittest.TestCase):
    def setUp(self):
        self._saved = {
            k: os.environ.get(k)
            for k in ("PRISMOR_HOME", "PRISMOR_AGENT_KEY", "PRISMOR_AGENT_LABEL", "PRISMOR_API_BASE")
        }
        self.home = Path(tempfile.mkdtemp(prefix="prismor-env-ident-"))
        os.environ["PRISMOR_HOME"] = str(self.home)
        for k in ("PRISMOR_AGENT_KEY", "PRISMOR_AGENT_LABEL", "PRISMOR_API_BASE"):
            os.environ.pop(k, None)

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_no_env_no_file_means_not_enrolled(self):
        self.assertIsNone(_identity.load_identity())
        self.assertFalse(_identity.is_enrolled())

    def test_env_key_is_a_full_identity(self):
        os.environ["PRISMOR_AGENT_KEY"] = "prism_agent_" + "a" * 64
        ident = _identity.load_identity()
        self.assertIsNotNone(ident)
        self.assertEqual(ident["device_key"], os.environ["PRISMOR_AGENT_KEY"])
        self.assertEqual(ident["source"], "env")
        self.assertTrue(_identity.is_enrolled())

    def test_env_key_takes_precedence_over_identity_file(self):
        # A container image may ship a baked-in enrollment; the per-deployment
        # env key must win so one image can serve many workloads.
        _identity.save_identity({"device_key": "prism_dev_" + "b" * 64, "org_id": "org_file"})
        os.environ["PRISMOR_AGENT_KEY"] = "prism_agent_" + "a" * 64
        ident = _identity.load_identity()
        self.assertEqual(ident["device_key"], os.environ["PRISMOR_AGENT_KEY"])

    def test_env_identity_is_never_persisted(self):
        os.environ["PRISMOR_AGENT_KEY"] = "prism_agent_" + "a" * 64
        _identity.load_identity()
        self.assertFalse(_identity.identity_path().exists())

    def test_blank_env_key_is_ignored(self):
        os.environ["PRISMOR_AGENT_KEY"] = "   "
        self.assertIsNone(_identity.load_identity())

    def test_env_identity_carries_api_base_and_label(self):
        os.environ["PRISMOR_AGENT_KEY"] = "prism_agent_" + "a" * 64
        os.environ["PRISMOR_API_BASE"] = "https://staging.example.test"
        os.environ["PRISMOR_AGENT_LABEL"] = "checkout-bot prod"
        ident = _identity.load_identity()
        self.assertEqual(ident["api_base"], "https://staging.example.test")
        self.assertEqual(ident["label"], "checkout-bot prod")

    def test_file_identity_still_works_without_env(self):
        _identity.save_identity({"device_key": "prism_dev_" + "b" * 64, "org_id": "org_file"})
        ident = _identity.load_identity()
        self.assertEqual(ident["org_id"], "org_file")


if __name__ == "__main__":
    unittest.main()
