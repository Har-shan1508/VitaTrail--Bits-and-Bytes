"""Secure sharing: scoped, expiring, revocable links for one doctor.

The link carries a signed JWT that points at a share row. The signature stops tampering and the
expiry is enforced cryptographically; the row holds the scope and the revoked flag, so the
patient can cut access instantly. Tier-3 (restricted) records additionally need a one-time PIN
that the patient reads out to the doctor.
"""
import json
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from flask import abort

from . import alerts, config, crypto, records
from .classify import CATEGORIES, SENSITIVE

ALLOWED_MONTHS = (0, 1, 3, 6, 12)
PRESETS = [  # smart defaults by specialty: the patient doesn't have to decide what is relevant
    {"id": "gp", "label": "General physician", "categories": ["general", "diabetes", "cardiology", "respiratory"],
     "months": 3, "hours": 24, "summary_only": False},
    {"id": "emergency", "label": "Emergency / ER (safety summary only)", "categories": [],
     "months": 0, "hours": 2, "summary_only": True},
    {"id": "cardio", "label": "Cardiologist", "categories": ["cardiology", "diabetes", "general"],
     "months": 12, "hours": 24, "summary_only": False},
    {"id": "diabetes", "label": "Diabetes specialist", "categories": ["diabetes", "cardiology", "general"],
     "months": 12, "hours": 24, "summary_only": False},
    {"id": "ortho", "label": "Orthopaedic doctor", "categories": ["orthopedics", "general"],
     "months": 12, "hours": 24, "summary_only": False},
    {"id": "pulmo", "label": "Lung specialist", "categories": ["respiratory", "general"],
     "months": 12, "hours": 24, "summary_only": False},
    {"id": "custom", "label": "Custom", "categories": [], "months": 3, "hours": 24, "summary_only": False},
]


def now():
    return datetime.now(timezone.utc)


def _ts(text):
    return datetime.fromisoformat(text)


def build_scope(body):
    cats = [c for c in body.get("categories") or [] if c in CATEGORIES and c not in SENSITIVE]
    tiers = {1, 2} if body.get("include_tier2", True) else {1}
    if body.get("include_tier3"):
        tiers.add(3)
        cats += sorted(SENSITIVE)
    summary_only = bool(body.get("summary_only"))
    months = body.get("months", 3)
    months = months if months in ALLOWED_MONTHS else 3
    if not cats and not summary_only:
        raise ValueError("Pick at least one type of record, or choose safety summary only.")
    since = None if (months == 0 or summary_only) else (now() - timedelta(days=round(months * 30.4))).date().isoformat()
    return {"categories": cats, "tiers": sorted(tiers), "months": months, "since": since, "summary_only": summary_only}


def token_for(row):
    return crypto.sign_token({"typ": "share", "sid": row["id"], "pid": row["patient_id"],
                              "iat": int(_ts(row["created_at"]).timestamp()), "exp": int(_ts(row["expires_at"]).timestamp())})


def status(row):
    if row["revoked_at"]:
        return "revoked"
    return "expired" if _ts(row["expires_at"]) <= now() else "active"


def public(row, base_url):
    st = status(row)
    scope = json.loads(row["scope"])
    return {"id": row["id"], "label": row["label"], "status": st, "created_at": row["created_at"],
            "expires_at": row["expires_at"], "views": row["views"], "last_viewed_at": row["last_viewed_at"],
            "scope": {**scope, "pin_protected": bool(row["pin_hash"])},
            "url": f"{base_url}/s/{token_for(row)}" if st == "active" else None}


def create(db, patient_id, body):
    label = str(body.get("label") or "").strip()[:80]
    if not label:
        raise ValueError("Say who this link is for, e.g. Dr. Sharma.")
    hours = body.get("hours")
    if not isinstance(hours, int) or not (1 <= hours <= 24 * 14):
        raise ValueError("Choose how long the link should work.")
    scope = build_scope(body)
    sid, created = secrets.token_urlsafe(6), now()
    pin = f"{secrets.randbelow(10**6):06d}" if 3 in scope["tiers"] else None
    db.execute("INSERT INTO shares(id,patient_id,label,scope,pin_hash,created_at,expires_at) VALUES (?,?,?,?,?,?,?)",
               (sid, patient_id, label, json.dumps(scope), crypto.pin_digest(sid, pin) if pin else None,
                created.isoformat(timespec="seconds"), (created + timedelta(hours=hours)).isoformat(timespec="seconds")))
    return db.execute("SELECT * FROM shares WHERE id=?", (sid,)).fetchone(), pin


def resolve(db, token):
    """Verify the link's signature and expiry, then check it hasn't been revoked."""
    try:
        claims = crypto.read_token(token, "share")
    except jwt.ExpiredSignatureError:
        abort(410, "This link has expired. Ask the patient for a new one.")
    except jwt.InvalidTokenError:
        abort(401, "This link is not valid.")
    row = db.execute("SELECT * FROM shares WHERE id=?", (claims["sid"],)).fetchone()
    if not row:
        abort(404, "This link does not exist.")
    if row["revoked_at"]:
        abort(410, "The patient has stopped sharing these records.")
    if status(row) == "expired":
        abort(410, "This link has expired. Ask the patient for a new one.")
    return row


def view(db, row, patient, pin, today):
    """What the doctor sees: only what the scope allows. Tier 3 stays locked until the PIN is right."""
    scope = json.loads(row["scope"])
    pin_state = {"required": 3 in scope["tiers"], "unlocked": False, "error": None, "locked_count": 0}
    if pin_state["required"] and pin:
        if row["pin_failures"] >= config.MAX_PIN_FAILS:
            pin_state["error"] = "Too many wrong PINs. Ask the patient to create a new link."
        elif crypto.pin_matches(row["id"], pin, row["pin_hash"]):
            pin_state["unlocked"] = True
        else:
            db.execute("UPDATE shares SET pin_failures = pin_failures + 1 WHERE id=?", (row["id"],))
            db.commit()
            left = config.MAX_PIN_FAILS - row["pin_failures"] - 1
            pin_state["error"] = f"That PIN is not correct. {max(left, 0)} tries left."
    allowed = {1, 2} | ({3} if pin_state["unlocked"] else set())

    everything = records.load_records(db, patient)
    safe = [r for r in everything if r["tier"] in allowed]
    state = alerts.build_state(safe)
    in_scope = lambda r: (r["category"] in scope["categories"] and r["tier"] in scope["tiers"]
                          and (not scope["since"] or r["date"] >= scope["since"]))
    timeline = [] if scope["summary_only"] else [r for r in safe if in_scope(r)]
    if pin_state["required"] and not pin_state["unlocked"] and not scope["summary_only"]:
        pin_state["locked_count"] = sum(1 for r in everything if r["tier"] == 3 and in_scope(r))
    return {"summary": alerts.build_summary(state, today), "alerts": alerts.evaluate(state, today),
            "records": timeline, "pin": pin_state,
            "scope": {k: scope[k] for k in ("categories", "months", "summary_only")} | {"tier3": 3 in scope["tiers"]}}
