"""Issuing and reading medical records.

Issue:  classify -> encrypt with the patient's data key (AES-GCM) -> sign with the hospital's
        Ed25519 key -> store.  Prescriptions also create medicine-reminder plans.
Read:   verify the hospital signature -> decrypt -> hand back plain data plus an integrity flag.
"""
import hashlib
import json
import uuid
from datetime import datetime, timezone

from . import crypto, meds
from .classify import RECORD_TYPES, classify

TEXT_FIELDS = {
    "consultation": ["diagnosis", "notes", "allergies"],
    "imaging": ["modality", "body_part", "findings"],
    "vitals": ["bp", "pulse", "weight", "spo2", "temp", "glucose"],
    "procedure": ["procedure", "outcome", "notes"],
}


def _text(value, limit=2000):
    return str(value or "").strip()[:limit]


def _int(value, lo, hi, default):
    try:
        return max(lo, min(hi, int(value)))
    except (TypeError, ValueError):
        return default


def clean(rtype, data):
    """Keep only known fields, coerce types, reject empty prescriptions. Raises ValueError."""
    data = data if isinstance(data, dict) else {}
    if rtype == "prescription":
        items = [{"name": _text(m.get("name"), 80), "dose": _text(m.get("dose"), 40),
                  "times": _int(m.get("times"), 1, 4, 1), "days": _int(m.get("days"), 1, 365, 7),
                  "instructions": _text(m.get("instructions"), 120)}
                 for m in (data.get("medications") or [])[:12] if isinstance(m, dict) and _text(m.get("name"))]
        if not items:
            raise ValueError("Add at least one medicine.")
        return {"medications": items}
    if rtype == "lab":
        items = [{"name": _text(t.get("name"), 80), "value": _text(t.get("value"), 30), "unit": _text(t.get("unit"), 20),
                  "range": _text(t.get("range"), 30), "flag": _text(t.get("flag"), 10)}
                 for t in (data.get("tests") or [])[:30] if isinstance(t, dict) and _text(t.get("name"))]
        if not items:
            raise ValueError("Add at least one test.")
        return {"tests": items}
    out = {k: _text(data.get(k)) for k in TEXT_FIELDS[rtype]}
    if rtype == "consultation":
        out["chronic"] = bool(data.get("chronic"))
        if not out["diagnosis"]:
            raise ValueError("Add a diagnosis.")
    return out


def _aad(patient_id, record_id):
    return f"rec:{patient_id}:{record_id}".encode()


def _message(rid, pid, hid, rtype, category, tier, rdate, ciphertext):
    """What the hospital signs: the metadata plus a hash of the ciphertext."""
    return crypto.canonical({"id": rid, "pid": pid, "hid": hid, "type": rtype, "cat": category, "tier": tier,
                             "date": rdate, "ct": hashlib.sha256(ciphertext.encode()).hexdigest()})


def create_record(db, hospital, patient, rtype, title, rdate, data, category=None, restricted=False):
    if rtype not in RECORD_TYPES:
        raise ValueError("Unknown record type.")
    title = _text(title, 200)
    if not title:
        raise ValueError("Add a title.")
    data = clean(rtype, data)
    cat, tier = classify(rtype, title, data, category, restricted)
    rid = uuid.uuid4().hex[:12]
    dek = crypto.open_data_key(patient["data_key_enc"], patient["id"])
    ct = crypto.seal(dek, crypto.canonical({"title": title, "data": data}), _aad(patient["id"], rid))
    sig = crypto.sign(hospital["signing_key_enc"], hospital["id"],
                      _message(rid, patient["id"], hospital["id"], rtype, cat, tier, rdate, ct))
    created = datetime.now(timezone.utc).isoformat(timespec="seconds")
    db.execute("INSERT INTO records(id,patient_id,hospital_id,record_type,category,tier,record_date,created_at,ciphertext,signature)"
               " VALUES (?,?,?,?,?,?,?,?,?,?)", (rid, patient["id"], hospital["id"], rtype, cat, tier, rdate, created, ct, sig))
    plans = meds.create_plans(db, patient["id"], rid, rdate, data["medications"]) if rtype == "prescription" else 0
    return {"id": rid, "category": cat, "tier": tier, "plans_created": plans}


def read_record(row, dek, hospitals):
    h = hospitals[row["hospital_id"]]
    signed = crypto.verify(h["public_key"], row["signature"], _message(
        row["id"], row["patient_id"], row["hospital_id"], row["record_type"], row["category"],
        row["tier"], row["record_date"], row["ciphertext"]))
    try:
        content = json.loads(crypto.unseal(dek, row["ciphertext"], _aad(row["patient_id"], row["id"])))
        title, data, readable = content["title"], content["data"], True
    except Exception:  # InvalidTag etc.: ciphertext was altered
        title, data, readable = "Unreadable record", {}, False
    return {
        "id": row["id"], "type": row["record_type"], "category": row["category"], "tier": row["tier"],
        "date": row["record_date"], "created_at": row["created_at"], "title": title, "data": data,
        "hospital": {"id": h["id"], "name": h["name"], "fingerprint": crypto.fingerprint(h["public_key"])},
        "verified": signed and readable,
        "integrity": "ok" if signed and readable else ("signature_invalid" if readable else "decrypt_failed"),
    }


def hospitals_by_id(db):
    return {h["id"]: h for h in db.execute("SELECT * FROM hospitals")}


def load_records(db, patient):
    """All of a patient's records, decrypted and verified, newest first."""
    hosp = hospitals_by_id(db)
    dek = crypto.open_data_key(patient["data_key_enc"], patient["id"])
    rows = db.execute("SELECT * FROM records WHERE patient_id=? ORDER BY record_date DESC, created_at DESC",
                      (patient["id"],)).fetchall()
    return [read_record(r, dek, hosp) for r in rows]
