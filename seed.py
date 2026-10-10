"""Simulated demo data (allowed by the hackathon rules). Dates are relative to today so the demo
always looks fresh. Every record goes through the real pipeline: classify, encrypt, sign."""
import uuid
from datetime import date, datetime, timedelta, timezone

import crypto, records
from db import TABLES

PASSWORD = "demo123"
HOSPITALS = [  # id, name, kind, login
    ("cgh", "City General Hospital", "hospital", "citygeneral"),
    ("shc", "Sunrise Heart Clinic", "clinic", "sunrise"),
    ("lvd", "Lakeview Diagnostics", "lab", "lakeview"),
    ("moc", "Metro Orthopaedic Centre", "clinic", "metroortho"),
    ("mwc", "MindWell Clinic", "clinic", "mindwell"),
]
PATIENTS = [  # id, health id, name, dob, sex, blood group, login
    ("p1", "VT-1001", "Ravi Kumar", "1973-04-12", "Male", "B+", "ravi"),
    ("p2", "VT-1002", "Meera Nair", "1997-08-23", "Female", "O+", "meera"),
]


def _med(name, dose, times, days, instructions=""):
    return {"name": name, "dose": dose, "times": times, "days": days, "instructions": instructions}


def _test(name, value, unit, ref, flag=""):
    return {"name": name, "value": value, "unit": unit, "range": ref, "flag": flag}


def _records(ago):
    """(patient, hospital, type, days ago, title, data, category override)"""
    return [
        # ---- Ravi Kumar: diabetes + hypertension, seen at four providers --------------------
        ("p1", "cgh", "procedure", 1100, "Appendicectomy", {"procedure": "Laparoscopic appendicectomy", "outcome": "Uneventful recovery"}, None),
        ("p1", "cgh", "consultation", 210, "Type 2 diabetes follow-up",
         {"diagnosis": "Type 2 diabetes mellitus", "chronic": True, "allergies": "Penicillin (rash)",
          "notes": "Diet counselling given. Continue metformin."}, None),
        ("p1", "shc", "consultation", 150, "Blood pressure review",
         {"diagnosis": "Essential hypertension", "chronic": True, "notes": "BP 148/92. Started amlodipine."}, None),
        ("p1", "mwc", "consultation", 40, "Stress and sleep review",
         {"diagnosis": "Generalised anxiety disorder (mild)", "chronic": True,
          "notes": "Weekly counselling. Low-dose antidepressant started."}, None),
        ("p1", "mwc", "prescription", 40, "Antidepressant course",
         {"medications": [_med("Sertraline", "50 mg", 1, 60, "Morning, with food")]}, None),
        ("p1", "shc", "prescription", 35, "Heart medicines",
         {"medications": [_med("Amlodipine", "5 mg", 1, 90, "Morning"), _med("Atorvastatin", "10 mg", 1, 90, "Night"),
                          _med("Aspirin", "75 mg", 1, 90, "After lunch")]}, None),
        ("p1", "cgh", "prescription", 20, "Diabetes medicines",
         {"medications": [_med("Metformin", "500 mg", 2, 90, "After meals")]}, None),
        ("p1", "lvd", "lab", 14, "Lipid profile",
         {"tests": [_test("Total cholesterol", "212", "mg/dL", "< 200", "high"), _test("LDL cholesterol", "138", "mg/dL", "< 100", "high"),
                    _test("HDL cholesterol", "41", "mg/dL", "> 40"), _test("Triglycerides", "165", "mg/dL", "< 150", "high")]}, None),
        ("p1", "lvd", "lab", 12, "HbA1c and fasting glucose",
         {"tests": [_test("HbA1c", "7.9", "%", "< 7.0", "high"), _test("Fasting glucose", "142", "mg/dL", "70-100", "high")]}, "diabetes"),
        ("p1", "shc", "lab", 9, "Lipid profile (clinic lab)",
         {"tests": [_test("Total cholesterol", "208", "mg/dL", "< 200", "high"), _test("LDL cholesterol", "134", "mg/dL", "< 100", "high"),
                    _test("HDL cholesterol", "42", "mg/dL", "> 40"), _test("Triglycerides", "160", "mg/dL", "< 150", "high")]}, None),
        ("p1", "moc", "imaging", 6, "Right knee X-ray",
         {"modality": "X-ray", "body_part": "Right knee", "findings": "Mild joint-space narrowing. Early osteoarthritis."}, None),
        ("p1", "moc", "prescription", 6, "Knee pain relief",
         {"medications": [_med("Diclofenac", "50 mg", 2, 10, "After food"), _med("Pantoprazole", "40 mg", 1, 10, "Before breakfast")]}, "orthopedics"),
        ("p1", "cgh", "vitals", 3, "Clinic vitals",
         {"bp": "142/88", "pulse": "78", "weight": "82 kg", "spo2": "98%", "temp": "36.8 C"}, "general"),
        # ---- Meera Nair: asthma ---------------------------------------------------------------
        ("p2", "cgh", "consultation", 100, "Asthma review",
         {"diagnosis": "Mild persistent asthma", "chronic": True, "allergies": "Sulfa drugs; dust mites",
          "notes": "Triggers: dust and cold air. Inhaler technique checked."}, None),
        ("p2", "lvd", "lab", 20, "Complete blood count",
         {"tests": [_test("Haemoglobin", "12.4", "g/dL", "12-15"), _test("WBC count", "7200", "/uL", "4000-11000")]}, "general"),
        ("p2", "cgh", "prescription", 15, "Asthma controller",
         {"medications": [_med("Budesonide inhaler", "200 mcg", 2, 60, "Rinse mouth after use"),
                          _med("Montelukast", "10 mg", 1, 30, "Bedtime")]}, "respiratory"),
    ]


def seed(db):
    now = datetime.now(timezone.utc)
    today = now.date()
    for hid, name, kind, login in HOSPITALS:
        pub, enc = crypto.new_signing_key(hid)
        db.execute("INSERT INTO hospitals VALUES (?,?,?,?,?)", (hid, name, kind, pub, enc))
        db.execute("INSERT INTO users VALUES (?,?,?,?,?,?)", (uuid.uuid4().hex, login, crypto.hash_password(PASSWORD), "hospital", hid, name))
    for pid, health_id, name, dob, sex, blood, login in PATIENTS:
        _, enc = crypto.new_data_key(pid)
        db.execute("INSERT INTO patients VALUES (?,?,?,?,?,?,?)", (pid, health_id, name, dob, sex, blood, enc))
        db.execute("INSERT INTO users VALUES (?,?,?,?,?,?)", (uuid.uuid4().hex, login, crypto.hash_password(PASSWORD), "patient", pid, name))
    db.commit()

    hospitals = {h["id"]: h for h in db.execute("SELECT * FROM hospitals")}
    patients = {p["id"]: p for p in db.execute("SELECT * FROM patients")}
    for pid, hid, rtype, ago, title, data, cat in _records(None):
        rdate = (today - timedelta(days=ago)).isoformat()
        made = records.create_record(db, hospitals[hid], patients[pid], rtype, title, rdate, data, cat)
        for plan in db.execute("SELECT * FROM med_plans WHERE record_id=?", (made["id"],)).fetchall():
            _backfill_doses(db, plan, today, now)
    db.commit()


def _backfill_doses(db, plan, today, now):
    """Pretend the patient has been taking medicines for a while: ~90% of past doses are ticked off."""
    start = date.fromisoformat(plan["start_date"])
    for i in range((today - start).days):  # days before today
        for slot in range(plan["times_per_day"]):
            if (i * 5 + slot * 3 + plan["med_idx"] * 2) % 9 == 0:
                continue  # a missed dose
            day = (start + timedelta(days=i)).isoformat()
            db.execute("INSERT OR IGNORE INTO dose_logs VALUES (?,?,?,?)", (plan["id"], day, slot, now.isoformat(timespec="seconds")))


def seed_if_empty(db):
    if not db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        seed(db)


def reset(db):
    for table in TABLES:
        db.execute(f"DELETE FROM {table}")
    db.commit()
    seed(db)
