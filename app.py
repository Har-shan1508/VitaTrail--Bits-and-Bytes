"""VitaTrail: API + frontend in one Flask app (one service to deploy, no CORS)."""
import re
from datetime import date, datetime, timedelta, timezone
from functools import wraps

from flask import Flask, abort, g, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from . import alerts, config, crypto, meds, records, seed, shares
from .classify import CATEGORIES, RECORD_TYPES, classify
from .db import close_db, connect, get_db, init_db

app = Flask(__name__, static_folder=str(config.FRONTEND_DIR), static_url_path="/static")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
app.teardown_appcontext(close_db)

CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
       "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; "
       "img-src 'self' data:; connect-src 'self'; worker-src 'self'; frame-ancestors 'none'; base-uri 'none'")
TIERS = {"1": {"label": "Routine", "hint": "Vitals, routine labs, prescriptions"},
         "2": {"label": "Specialist", "hint": "Imaging, surgery, chronic-condition notes"},
         "3": {"label": "Restricted", "hint": "Mental health, sexual and reproductive health"}}

def utc_now():
    return datetime.now(timezone.utc)

def iso_now():
    return utc_now().isoformat(timespec="seconds")

def client_today():
    try:
        d = date.fromisoformat(request.args.get("today", ""))
        if abs((d - utc_now().date()).days) <= 2:
            return d
    except ValueError:
        pass
    return utc_now().date()

def needs(role):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            header = request.headers.get("Authorization", "")
            try:
                claims = crypto.read_token(header[7:], "session") if header.startswith("Bearer ") else None
            except Exception:
                claims = None
            if not claims:
                abort(401, "Please sign in again.")
            if claims["role"] != role:
                abort(403, "This page is for a different kind of account.")
            g.user = claims
            return fn(*args, **kwargs)
        return wrapper
    return deco

def patient_card(p, today):
    dob = date.fromisoformat(p["dob"])
    age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
    return {"name": p["name"], "health_id": p["health_id"], "age": age, "sex": p["sex"], "blood_group": p["blood_group"]}

def my_patient(db):
    return db.execute("SELECT * FROM patients WHERE id=?", (g.user["ref"],)).fetchone()

def patient_by_health_id(db, health_id):
    row = db.execute("SELECT * FROM patients WHERE health_id=?", (str(health_id or "").strip().upper(),)).fetchone()
    return row or abort(404, "No patient with that Health ID.")

@app.errorhandler(HTTPException)
def http_error(e):
    return jsonify(error=e.description or e.name), e.code

@app.after_request
def secure_headers(resp):
    resp.headers.update({"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
                         "X-Frame-Options": "DENY", "Content-Security-Policy": CSP})
    if request.path.startswith(("/api/", "/s/")):
        resp.headers["Cache-Control"] = "no-store"
    return resp

@app.get("/")
@app.get("/s/<token>")
def index(token=None):
    return send_from_directory(config.FRONTEND_DIR, "index.html")

@app.get("/sw.js")
def service_worker():
    return send_from_directory(config.FRONTEND_DIR, "sw.js", mimetype="application/javascript")

@app.get("/healthz")
def healthz():
    return "ok"

@app.get("/api/meta")
def meta():
    return jsonify(categories=CATEGORIES, record_types=RECORD_TYPES, presets=shares.PRESETS, tiers=TIERS,
                   demo=config.DEMO_MODE)

@app.post("/api/auth/login")
def login():
    body = request.get_json(silent=True) or {}
    user = get_db().execute("SELECT * FROM users WHERE username=?", (str(body.get("username", "")).strip().lower(),)).fetchone()
    password_ok = crypto.check_password(str(body.get("password", "")), user["pw_hash"] if user else "x$x$x")
    if not user or not password_ok:
        abort(401, "Wrong username or password.")
    now = int(utc_now().timestamp())
    token = crypto.sign_token({"typ": "session", "uid": user["id"], "role": user["role"], "ref": user["ref_id"],
                               "iat": now, "exp": now + config.SESSION_HOURS * 3600})
    return jsonify(token=token, role=user["role"], name=user["display"])

@app.get("/api/patient/vault")
@needs("patient")
def vault():
    db, today = get_db(), client_today()
    patient = my_patient(db)
    recs = records.load_records(db, patient)
    state = alerts.build_state(recs)
    return jsonify(patient=patient_card(patient, today), summary=alerts.build_summary(state, today),
                   alerts=alerts.evaluate(state, today), records=recs)

@app.get("/api/patient/ping")
@needs("patient")
def ping():
    row = get_db().execute("SELECT COUNT(*) c, COALESCE(MAX(created_at),'') m FROM records WHERE patient_id=?",
                           (g.user["ref"],)).fetchone()
    return jsonify(count=row["c"], latest=row["m"])

@app.get("/api/patient/meds")
@needs("patient")
def my_meds():
    db, today = get_db(), client_today()
    recs = records.load_records(db, my_patient(db))
    return jsonify(day=today.isoformat(), plans=meds.list_plans(db, g.user["ref"], recs, today))

@app.put("/api/patient/meds/<plan_id>/reminders")
@needs("patient")
def set_reminders(plan_id):
    body, db = request.get_json(silent=True) or {}, get_db()
    try:
        meds.set_reminders(db, g.user["ref"], plan_id, body.get("times"), body.get("enabled", True))
    except LookupError as e:
        abort(404, str(e))
    except ValueError as e:
        abort(400, str(e))
    db.commit()
    return jsonify(ok=True)

@app.post("/api/patient/doses")
@needs("patient")
def mark_dose():
    body, db = request.get_json(silent=True) or {}, get_db()
    try:
        meds.set_dose(db, g.user["ref"], body.get("plan_id"), body.get("day"), body.get("slot"), bool(body.get("taken", True)))
    except LookupError as e:
        abort(404, str(e))
    except ValueError as e:
        abort(400, str(e))
    db.commit()
    return jsonify(ok=True)

# ---- Feature 8: Community Health Camp Radar ----
@app.get("/api/patient/camps")
@needs("patient")
def patient_camps():
    db = get_db()
    patient = my_patient(db)
    recs = records.load_records(db, patient)
    state = alerts.build_state(recs)
    
    conditions_str = " ".join(state["conditions"]).lower()
    
    # Mock database of upcoming local health camps
    MOCK_CAMPS = [
        {"id": "c1", "title": "Lions Club Free Diabetic Screening", "target": "diabetes|hba1c|glucose", "location": "City Center Hall (1.2 km away)", "date": (utc_now().date() + timedelta(days=2)).isoformat()},
        {"id": "c2", "title": "Cardiac Wellness & BP Check", "target": "hypertens|heart|bp|cardi", "location": "Sunrise Heart Clinic (3.5 km away)", "date": (utc_now().date() + timedelta(days=5)).isoformat()},
        {"id": "c3", "title": "Free Asthma & Pulmonary Camp", "target": "asthma|copd|bronch", "location": "City General Hospital (2.0 km away)", "date": (utc_now().date() + timedelta(days=7)).isoformat()},
        {"id": "c4", "title": "Senior Orthopaedic Drive", "target": "arthritis|osteo|knee|fracture", "location": "Metro Orthopaedic Centre (4.1 km away)", "date": (utc_now().date() + timedelta(days=4)).isoformat()},
    ]
    
    recommended = []
    for camp in MOCK_CAMPS:
        if re.search(camp["target"], conditions_str, re.I):
            recommended.append(camp)
            
    return jsonify(camps=recommended)

@app.get("/api/patient/shares")
@needs("patient")
def list_shares():
    rows = get_db().execute("SELECT * FROM shares WHERE patient_id=? ORDER BY created_at DESC", (g.user["ref"],)).fetchall()
    return jsonify([shares.public(r, request.host_url.rstrip("/")) for r in rows])

@app.post("/api/patient/shares")
@needs("patient")
def create_share():
    db = get_db()
    try:
        row, pin = shares.create(db, g.user["ref"], request.get_json(silent=True) or {})
    except ValueError as e:
        abort(400, str(e))
    db.commit()
    return jsonify(share=shares.public(row, request.host_url.rstrip("/")), pin=pin), 201

@app.delete("/api/patient/shares/<sid>")
@needs("patient")
def revoke_share(sid):
    db = get_db()
    cur = db.execute("UPDATE shares SET revoked_at=? WHERE id=? AND patient_id=? AND revoked_at IS NULL",
                     (iso_now(), sid, g.user["ref"]))
    if not cur.rowcount:
        abort(404, "Link not found.")
    db.commit()
    return jsonify(ok=True)

@app.get("/api/shared/<token>")
def shared(token):
    db = get_db()
    row = shares.resolve(db, token)
    patient = db.execute("SELECT * FROM patients WHERE id=?", (row["patient_id"],)).fetchone()
    pin = (request.headers.get("X-Share-Pin") or "").strip()
    if not pin:
        db.execute("UPDATE shares SET views=views+1, last_viewed_at=? WHERE id=?", (iso_now(), row["id"]))
        db.commit()
    today = client_today()
    card = patient_card(patient, today)
    return jsonify(label=row["label"], expires_at=row["expires_at"],
                   patient={k: card[k] for k in ("name", "age", "sex", "blood_group")},
                   **shares.view(db, row, patient, pin, today))

@app.get("/api/hospital/me")
@needs("hospital")
def hospital_me():
    h = get_db().execute("SELECT * FROM hospitals WHERE id=?", (g.user["ref"],)).fetchone()
    return jsonify(name=h["name"], kind=h["kind"], fingerprint=crypto.fingerprint(h["public_key"]))

@app.get("/api/hospital/patients/<health_id>")
@needs("hospital")
def hospital_find_patient(health_id):
    db = get_db()
    patient = patient_by_health_id(db, health_id)
    state = alerts.build_state([r for r in records.load_records(db, patient) if r["tier"] < 3])
    return jsonify(patient=patient_card(patient, client_today()), allergies=state["allergies"], conditions=state["conditions"])

@app.post("/api/hospital/classify")
@needs("hospital")
def hospital_classify():
    b = request.get_json(silent=True) or {}
    category, tier = classify(b.get("record_type"), b.get("title"), b.get("data"), b.get("category") or None, bool(b.get("restricted")))
    return jsonify(category=category, tier=tier)

@app.post("/api/hospital/precheck")
@needs("hospital")
def hospital_precheck():
    b, db, today = request.get_json(silent=True) or {}, get_db(), client_today()
    patient = patient_by_health_id(db, b.get("health_id"))
    state = alerts.build_state(records.load_records(db, patient), with_restricted=False)
    names = lambda key: [str(x) for x in (b.get(key) or [])][:30]
    return jsonify(alerts=alerts.evaluate(state, today, new_meds=names("medications"), new_tests=names("tests"), mask=True))

@app.post("/api/hospital/records")
@needs("hospital")
def issue_record():
    b, db = request.get_json(silent=True) or {}, get_db()
    patient = patient_by_health_id(db, b.get("health_id"))
    hospital = db.execute("SELECT * FROM hospitals WHERE id=?", (g.user["ref"],)).fetchone()
    rdate = str(b.get("record_date") or utc_now().date().isoformat())
    try:
        if date.fromisoformat(rdate) > utc_now().date() + timedelta(days=1):
            abort(400, "The record date can't be in the future.")
    except ValueError:
        abort(400, "Choose a valid date.")
    try:
        made = records.create_record(db, hospital, patient, b.get("record_type"), b.get("title"), rdate,
                                     b.get("data"), b.get("category") or None, bool(b.get("restricted")))
    except ValueError as e:
        abort(400, str(e))
    db.commit()
    return jsonify(made), 201

@app.get("/api/hospital/records")
@needs("hospital")
def hospital_records():
    db = get_db()
    hosp = records.hospitals_by_id(db)
    rows = db.execute("SELECT r.*, p.name pname, p.health_id phid, p.data_key_enc dk FROM records r "
                      "JOIN patients p ON p.id=r.patient_id WHERE r.hospital_id=? ORDER BY r.created_at DESC, r.record_date DESC LIMIT 12",
                      (g.user["ref"],)).fetchall()
    out = []
    for row in rows:
        rec = records.read_record(row, crypto.open_data_key(row["dk"], row["patient_id"]), hosp)
        out.append({"id": rec["id"], "patient": row["pname"], "health_id": row["phid"], "type": rec["type"], "title": rec["title"],
                    "category": rec["category"], "tier": rec["tier"], "date": rec["date"], "integrity": rec["integrity"]})
    return jsonify(out)

@app.post("/api/demo/tamper/<record_id>")
@needs("hospital")
def demo_tamper(record_id):
    if not config.DEMO_MODE:
        abort(404, "Not available.")
    db = get_db()
    row = db.execute("SELECT * FROM records WHERE id=? AND hospital_id=?", (record_id, g.user["ref"])).fetchone()
    if not row:
        abort(404, "Record not found.")
    undo = bool((request.get_json(silent=True) or {}).get("undo"))
    moved = (date.fromisoformat(row["record_date"]) + timedelta(days=-1 if undo else 1)).isoformat()
    db.execute("UPDATE records SET record_date=? WHERE id=?", (moved, record_id))
    db.commit()
    return jsonify(ok=True)

@app.post("/api/demo/reset")
def demo_reset():
    if not config.DEMO_MODE:
        abort(404, "Not available.")
    seed.reset(get_db())
    return jsonify(ok=True)

def _boot():
    init_db()
    con = connect()
    seed.seed_if_empty(con)
    con.close()

_boot()