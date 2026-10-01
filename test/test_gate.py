"""Consumer identity and fail-closed CI checks (no mocked consensus claims)."""
import copy
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "cli"))
import attaint_gate
import envelope


class GateTests(unittest.TestCase):
    def setUp(self):
        self.evidence = {"version": "attaint/1", "package": "demo", "from_version": "1.0",
                         "to_version": "1.1", "facts": {}, "pin": {}}
        self.policy = {"policy_id": 0, "policy_hash": "pinned", "blocking": ["EGRESS"],
                       "min_level": 1, "min_rounds": 1}
        self.gate = {"att_id": 3, "policy_id": 0, "policy_hash": "pinned",
                     "envelope_hash": envelope.envelope_hash(self.evidence), "package": "demo",
                     "from_version": "1.0", "to_version": "1.1", "level": 1,
                     "rounds": 1, "gate": "CLEAN", "verdict": "CLEAN",
                     "findings": [], "inconclusive_classes": []}

    def verify(self, gate=None):
        return attaint_gate.verify_gate(gate or self.gate, self.policy, self.evidence,
                                       policy_id=0, policy_hash="pinned", attestation=3)

    def test_three_exit_codes(self):
        self.assertEqual(self.verify(), 0)
        self.gate.update(gate="RISK", verdict="EGRESS", findings=["EGRESS@network"])
        self.assertEqual(self.verify(), 1)
        self.gate.update(gate="INCONCLUSIVE", verdict="INCONCLUSIVE", findings=[])
        self.assertEqual(self.verify(), 2)

    def test_attestation_identity_must_match(self):
        for key, bad in [("policy_id", 1), ("policy_hash", "other"), ("att_id", 4),
                         ("envelope_hash", "forged"), ("package", "other"),
                         ("from_version", "0"), ("to_version", "2"), ("level", 2)]:
            gate = {**self.gate, key: bad}
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verify(gate)

    def test_local_declared_hash_cannot_be_forged(self):
        self.evidence["envelope_hash"] = "forged"
        with self.assertRaises(ValueError):
            self.verify()

    def test_clean_cannot_hide_missing_rounds_or_findings(self):
        for field, value in [("rounds", 0), ("findings", ["EGRESS@network"]),
                             ("inconclusive_classes", ["EGRESS"]), ("verdict", "EGRESS")]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify({**self.gate, field: value})

    def test_policy_or_unknown_result_cannot_pass(self):
        self.policy["policy_hash"] = "unrelated"
        with self.assertRaises(ValueError):
            self.verify()
        self.policy["policy_hash"] = "pinned"
        with self.assertRaises(ValueError):
            self.verify({**self.gate, "gate": "SAFE"})


if __name__ == "__main__":
    unittest.main()
