import json, sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cardtool

class TestValidate(unittest.TestCase):
    def test_my_card_is_valid(self):
        ok, errors, _ = cardtool.validate(cardtool.my_card())
        self.assertTrue(ok, f"my own card must validate, got: {errors}")

    def test_missing_required_field_fails(self):
        c = cardtool.my_card(); del c["skills"]
        ok, errors, _ = cardtool.validate(c)
        self.assertFalse(ok); self.assertTrue(any("skills" in e for e in errors))

    def test_empty_skill_field_fails(self):
        c = cardtool.my_card(); c["skills"][0]["description"] = ""
        ok, errors, _ = cardtool.validate(c)
        self.assertFalse(ok)

    def test_duplicate_skill_id_fails(self):
        c = cardtool.my_card(); c["skills"][1]["id"] = c["skills"][0]["id"]
        ok, errors, _ = cardtool.validate(c)
        self.assertFalse(ok); self.assertTrue(any("duplicate" in e for e in errors))

    def test_secret_leak_fails(self):
        c = cardtool.my_card(); c["description"] += " api_key: hunter2supersecret"
        ok, errors, _ = cardtool.validate(c)
        self.assertFalse(ok); self.assertTrue(any("secret" in e for e in errors))

    def test_non_https_url_fails(self):
        c = cardtool.my_card(); c["url"] = "http://example.com/card.json"
        ok, errors, _ = cardtool.validate(c)
        self.assertFalse(ok)

    def test_no_fake_payments_claim(self):
        # lab honesty rule: jarvis does not take payments; card must say so
        self.assertFalse(cardtool.my_card()["x402Support"])
        self.assertFalse(cardtool.my_card()["erc8004"]["active"])

if __name__ == "__main__":
    unittest.main(verbosity=2)
