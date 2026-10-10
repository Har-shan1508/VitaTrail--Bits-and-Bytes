"""Run with:  python -m unittest discover -s tests -v   (no extra packages needed)."""
import os
import sys
import tempfile
import unittest
from datetime import date

os.environ["DATA_DIR"] = tempfile.mkdtemp()  # isolated database + keys for the test run
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.app import app  # noqa: E402
from backend import crypto  # noqa: E402

TODAY = date.today().isoformat()


class VitaTrailTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c = app.test_client()
        cls.ravi = cls.login("ravi")
        cls.hospital = cls.login("citygeneral")

    @classmethod
    def login(cls, user):
        r = cls.c.post("/api/auth/login", json={"username": user, "password": "demo123"})
        assert r.status_code == 200, r.get_data(as_text=True)
        return {"Authorization": "Bearer " + r.get_json()["token"]}

    def get(self, url, headers=None):
        return self.c.get(url, headers=headers or self.ravi)

    # ---- auth -------------------------------------------------------------------------------
    def test_login_rejects_bad_password(self):
        r = self.c.post("/api/auth/login", json={"username": "ravi", "password": "nope"})
        self.assertEqual(r.status_code, 401)

    def test_roles_are_separated(self):
        self.assertEqual(self.c.get("/api/patient/vault", headers=self.hospital).status_code, 403)
        self.assertEqual(self.c.get("/api/hospital/me", headers=self.ravi).status_code, 403)
        self.assertEqual(self.c.get("/api/patient/vault").status_code, 401)

    # ---- vault: encryption, signatures, auto-tagging, safety alerts -------------------------------
    def test_vault_summary_and_tiers(self):
        v = self.get(f"/api/patient/vault?today={TODAY}").get_json()
        self.assertEqual(v["patient"]["blood_group"], "B+")
        self.assertIn("Penicillin (rash)", v["summary"]["allergies"])
        names = {m["name"] for m in v["summary"]["active_meds"]}
        self.assertTrue({"Metformin", "Amlodipine", "Diclofenac", "Sertraline"} <= names)
        self.assertTrue(all(r["verified"] for r in v["records"]))
        mental = [r for r in v["records"] if r["category"] == "mental_health"]
        self.assertTrue(mental and all(r["tier"] == 3 for r in mental))
        knee = next(r for r in v["records"] if r["title"] == "Right knee X-ray")
        self.assertEqual((knee["category"], knee["tier"]), ("orthopedics", 2))

    def test_alerts_find_cross_provider_problems(self):
        titles = [a["title"] for a in self.get(f"/api/patient/vault?today={TODAY}").get_json()["alerts"]]
        self.assertTrue(any("Diclofenac" in t and "Aspirin" in t for t in titles), titles)
        self.assertTrue(any(t.startswith("Repeated within") for t in titles), titles)

    def test_ciphertext_at_rest_is_unreadable(self):
        from backend.db import connect
        con = connect()
        row = con.execute("SELECT ciphertext FROM records LIMIT 1").fetchone()
        con.close()
        self.assertNotIn("diagnosis", row["ciphertext"])
        self.assertNotIn("Metformin", row["ciphertext"])

    # ---- hospital: pre-check + issuing -----------------------------------------------------------
    def test_precheck_flags_repeat_test_allergy_and_masks_restricted(self):
        r = self.c.post("/api/hospital/precheck", headers=self.hospital,
                        json={"health_id": "VT-1001", "tests": ["HbA1c"], "medications": ["Amoxicillin 500mg", "Tramadol"]})
        found = r.get_json()["alerts"]
        kinds = {a["kind"] for a in found}
        self.assertTrue({"duplicate_test", "allergy", "interaction"} <= kinds, found)
        self.assertNotIn("Sertraline", str(found))  # restricted drug is masked for the hospital

    def test_issue_record_syncs_to_patient_and_creates_reminders(self):
        before = self.get("/api/patient/ping").get_json()["count"]
        r = self.c.post("/api/hospital/records", headers=self.hospital, json={
            "health_id": "VT-1001", "record_type": "prescription", "title": "Cough syrup", "record_date": TODAY,
            "data": {"medications": [{"name": "Cetirizine", "dose": "10 mg", "times": 1, "days": 5, "instructions": "Night"}]}})
        self.assertEqual(r.status_code, 201, r.get_json())
        self.assertEqual(r.get_json()["plans_created"], 1)
        self.assertEqual(self.get("/api/patient/ping").get_json()["count"], before + 1)
        plans = self.get(f"/api/patient/meds?today={TODAY}").get_json()["plans"]
        plan = next(p for p in plans if p["name"] == "Cetirizine")
        self.assertEqual((plan["day_no"], plan["remaining"], plan["duration"]), (1, 5, 5))

    def test_validation(self):
        r = self.c.post("/api/hospital/records", headers=self.hospital,
                        json={"health_id": "VT-1001", "record_type": "prescription", "title": "x", "data": {"medications": []}})
        self.assertEqual(r.status_code, 400)
        r = self.c.post("/api/hospital/records", headers=self.hospital, json={"health_id": "VT-9999", "record_type": "lab"})
        self.assertEqual(r.status_code, 404)

    # ---- sharing: scope, PIN, expiry, revoke ---------------------------------------------------------
    def make_share(self, **over):
        body = {"label": "Dr. Sharma", "categories": ["general", "diabetes", "cardiology"], "months": 12, "hours": 24}
        body.update(over)
        r = self.c.post("/api/patient/shares", headers=self.ravi, json=body)
        self.assertEqual(r.status_code, 201, r.get_json())
        return r.get_json()

    def test_share_scope_hides_other_categories_and_restricted(self):
        made = self.make_share()
        token = made["share"]["url"].split("/s/")[1]
        self.assertIsNone(made["pin"])
        v = self.c.get(f"/api/shared/{token}?today={TODAY}").get_json()
        cats = {r["category"] for r in v["records"]}
        self.assertTrue(cats <= {"general", "diabetes", "cardiology"}, cats)
        self.assertFalse(v["pin"]["required"])
        self.assertNotIn("anxiety", str(v).lower())  # nothing from the mental-health record
        self.assertNotIn("Sertraline", str(v))

    def test_tier3_needs_pin_with_lockout(self):
        made = self.make_share(include_tier3=True)
        token, pin = made["share"]["url"].split("/s/")[1], made["pin"]
        self.assertEqual(len(pin), 6)
        locked = self.c.get(f"/api/shared/{token}?today={TODAY}").get_json()
        self.assertTrue(locked["pin"]["required"] and locked["pin"]["locked_count"] >= 1)
        self.assertNotIn("anxiety", str(locked).lower())
        wrong = self.c.get(f"/api/shared/{token}?today={TODAY}", headers={"X-Share-Pin": "000000" if pin != "000000" else "111111"}).get_json()
        self.assertFalse(wrong["pin"]["unlocked"])
        self.assertIn("tries left", wrong["pin"]["error"])
        ok = self.c.get(f"/api/shared/{token}?today={TODAY}", headers={"X-Share-Pin": pin}).get_json()
        self.assertTrue(ok["pin"]["unlocked"])
        self.assertTrue(any(r["category"] == "mental_health" for r in ok["records"]))

    def test_summary_only_share(self):
        made = self.make_share(summary_only=True, categories=[], hours=2)
        v = self.c.get("/api/shared/" + made["share"]["url"].split("/s/")[1]).get_json()
        self.assertEqual(v["records"], [])
        self.assertIn("Penicillin (rash)", v["summary"]["allergies"])

    def test_revoke_is_instant_and_tokens_cant_be_forged(self):
        made = self.make_share()
        token, sid = made["share"]["url"].split("/s/")[1], made["share"]["id"]
        self.assertEqual(self.c.get(f"/api/shared/{token}").status_code, 200)
        forged = token[:-3] + ("AAA" if not token.endswith("AAA") else "BBB")
        self.assertEqual(self.c.get(f"/api/shared/{forged}").status_code, 401)
        self.assertEqual(self.c.delete(f"/api/patient/shares/{sid}", headers=self.ravi).status_code, 200)
        self.assertEqual(self.c.get(f"/api/shared/{token}").status_code, 410)
        shares = self.get("/api/patient/shares").get_json()
        self.assertEqual(next(s for s in shares if s["id"] == sid)["status"], "revoked")

    def test_session_token_cannot_open_a_share_link(self):
        session_token = self.ravi["Authorization"].split(" ")[1]
        self.assertEqual(self.c.get(f"/api/shared/{session_token}").status_code, 401)

    def test_expired_link_is_rejected(self):
        import jwt
        from backend import config
        token = jwt.encode({"typ": "share", "sid": "x", "exp": 1}, config.SECRET_KEY, algorithm="HS256")
        self.assertEqual(self.c.get(f"/api/shared/{token}").status_code, 410)

    # ---- hospital signatures: tamper detection ------------------------------------------------------------
    def test_tampering_is_detected_and_reversible(self):
        recs = self.c.get("/api/hospital/records", headers=self.hospital).get_json()
        rid = recs[0]["id"]
        self.assertEqual(recs[0]["integrity"], "ok")
        self.c.post(f"/api/demo/tamper/{rid}", headers=self.hospital, json={})
        after = next(r for r in self.c.get("/api/hospital/records", headers=self.hospital).get_json() if r["id"] == rid)
        self.assertEqual(after["integrity"], "signature_invalid")
        self.c.post(f"/api/demo/tamper/{rid}", headers=self.hospital, json={"undo": True})
        again = next(r for r in self.c.get("/api/hospital/records", headers=self.hospital).get_json() if r["id"] == rid)
        self.assertEqual(again["integrity"], "ok")

    def test_crypto_primitives(self):
        key = os.urandom(32)
        blob = crypto.seal(key, b"secret", b"ctx")
        self.assertEqual(crypto.unseal(key, blob, b"ctx"), b"secret")
        with self.assertRaises(Exception):
            crypto.unseal(key, blob, b"other-context")
        pub, wrapped = crypto.new_signing_key("h")
        sig = crypto.sign(wrapped, "h", b"msg")
        self.assertTrue(crypto.verify(pub, sig, b"msg"))
        self.assertFalse(crypto.verify(pub, sig, b"msg2"))

    # ---- medicine reminders + day tracking ------------------------------------------------------------------
    def test_reminders_and_course_progress(self):
        data = self.get(f"/api/patient/meds?today={TODAY}").get_json()
        plan = next(p for p in data["plans"] if p["name"] == "Metformin")
        self.assertEqual(plan["status"], "active")
        self.assertEqual(plan["day_no"] + plan["remaining"] - (0 if plan["days_taken"] else 0) >= plan["duration"], True)
        # patient picks their own reminder times
        r = self.c.put(f"/api/patient/meds/{plan['id']}/reminders", headers=self.ravi, json={"times": ["07:30", "21:15"], "enabled": True})
        self.assertEqual(r.status_code, 200)
        r = self.c.put(f"/api/patient/meds/{plan['id']}/reminders", headers=self.ravi, json={"times": ["07:30"], "enabled": True})
        self.assertEqual(r.status_code, 400)  # needs one time per daily dose
        # tick today's doses
        for slot in (0, 1):
            r = self.c.post("/api/patient/doses", headers=self.ravi, json={"plan_id": plan["id"], "day": TODAY, "slot": slot, "taken": True})
            self.assertEqual(r.status_code, 200)
        plan2 = next(p for p in self.get(f"/api/patient/meds?today={TODAY}").get_json()["plans"] if p["id"] == plan["id"])
        self.assertEqual(plan2["reminder_times"], ["07:30", "21:15"])
        self.assertEqual(plan2["days_taken"], plan["days_taken"] + 1)
        self.assertEqual(plan2["remaining"], plan["remaining"] - 1)
        self.assertGreaterEqual(plan2["streak"], 1)
        # undo
        self.c.post("/api/patient/doses", headers=self.ravi, json={"plan_id": plan["id"], "day": TODAY, "slot": 1, "taken": False})
        plan3 = next(p for p in self.get(f"/api/patient/meds?today={TODAY}").get_json()["plans"] if p["id"] == plan["id"])
        self.assertEqual(plan3["days_taken"], plan["days_taken"])

    def test_cannot_touch_another_patients_medicines(self):
        meera = self.login("meera")
        mine = self.get(f"/api/patient/meds?today={TODAY}").get_json()["plans"][0]
        r = self.c.post("/api/patient/doses", headers=meera, json={"plan_id": mine["id"], "day": TODAY, "slot": 0, "taken": True})
        self.assertEqual(r.status_code, 404)


if __name__ == "__main__":
    unittest.main()
