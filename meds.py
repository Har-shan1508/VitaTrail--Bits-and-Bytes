"""Medicine reminders and course tracking (the extra feature).

A prescription issued by a hospital creates one plan per medicine. The PATIENT chooses the
reminder time for every daily dose and ticks each dose off. From the dose log we work out how
many days were completed, how many days remain, the streak and the adherence percentage.
"""
import json
import re
import uuid
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone

DEFAULT_TIMES = {1: ["08:00"], 2: ["08:00", "20:00"], 3: ["08:00", "14:00", "20:00"],
                 4: ["06:00", "12:00", "18:00", "22:00"]}
TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def create_plans(db, patient_id, record_id, start, medications):
    for idx, m in enumerate(medications):
        db.execute("INSERT INTO med_plans(id,patient_id,record_id,med_idx,start_date,duration_days,times_per_day,reminder_times)"
                   " VALUES (?,?,?,?,?,?,?,?)",
                   (uuid.uuid4().hex[:10], patient_id, record_id, idx, start, m["days"], m["times"],
                    json.dumps(DEFAULT_TIMES[m["times"]])))
    return len(medications)


def _plan_view(p, med, rec, logged, today):
    start = date.fromisoformat(p["start_date"])
    n, per = p["duration_days"], p["times_per_day"]
    end = start + timedelta(days=n - 1)
    times = json.loads(p["reminder_times"])
    status = "upcoming" if today < start else "completed" if today > end else "active"
    day_no = max(0, min(n, (today - start).days + 1))

    def taken_on(d):
        return sum((d.isoformat(), s) in logged for s in range(per))

    grid, full, partial, missed, past_taken = [], 0, 0, 0, 0
    for i in range(n):
        d = start + timedelta(days=i)
        t = taken_on(d)
        if d > today:
            state = "future"
        elif t >= per:
            state, full = "full", full + 1
        elif t > 0:
            state, partial = "partial", partial + (d < today)
        elif d == today:
            state = "today"
        else:
            state, missed = "missed", missed + 1
        if d < today:
            past_taken += t
        grid.append({"d": d.isoformat(), "s": state})

    today_full = status == "active" and taken_on(today) >= per
    anchor = today if today_full else today - timedelta(days=1)
    streak, d = 0, min(anchor, end)
    while d >= start and taken_on(d) >= per:
        streak, d = streak + 1, d - timedelta(days=1)

    past_days = max(0, min(n, (today - start).days))
    remaining = 0 if status == "completed" else n if status == "upcoming" else (end - today).days + (0 if today_full else 1)
    return {
        "id": p["id"], "name": med["name"], "dose": med.get("dose", ""), "instructions": med.get("instructions", ""),
        "hospital": rec["hospital"]["name"], "prescribed_on": rec["date"], "tier": rec["tier"],
        "times_per_day": per, "reminder_times": times, "reminders_on": bool(p["reminders_on"]),
        "start": start.isoformat(), "end": end.isoformat(), "duration": n, "status": status, "day_no": day_no,
        "remaining": remaining, "days_taken": full, "days_partial": partial, "days_missed": missed, "streak": streak,
        "adherence": round(100 * past_taken / (per * past_days)) if past_days else None,
        "today": [{"slot": i, "time": times[i], "taken": (today.isoformat(), i) in logged} for i in range(per)]
        if status == "active" else [],
        "grid": grid,
    }


def list_plans(db, patient_id, records, today):
    by_id = {r["id"]: r for r in records}
    logs = defaultdict(set)
    for row in db.execute("SELECT plan_id, day, slot FROM dose_logs WHERE plan_id IN "
                          "(SELECT id FROM med_plans WHERE patient_id=?)", (patient_id,)):
        logs[row["plan_id"]].add((row["day"], row["slot"]))
    out = []
    for p in db.execute("SELECT * FROM med_plans WHERE patient_id=? ORDER BY start_date DESC", (patient_id,)):
        rec = by_id.get(p["record_id"])
        items = rec["data"].get("medications", []) if rec else []
        if p["med_idx"] < len(items):
            out.append(_plan_view(p, items[p["med_idx"]], rec, logs[p["id"]], today))
    order = {"active": 0, "upcoming": 1, "completed": 2}
    return sorted(out, key=lambda x: (order[x["status"]], x["name"].lower()))


def _plan(db, patient_id, plan_id):
    return db.execute("SELECT * FROM med_plans WHERE id=? AND patient_id=?", (plan_id, patient_id)).fetchone()


def set_reminders(db, patient_id, plan_id, times, enabled):
    p = _plan(db, patient_id, plan_id)
    if not p:
        raise LookupError("Medicine not found.")
    if (not isinstance(times, list) or len(times) != p["times_per_day"]
            or not all(isinstance(t, str) and TIME_RE.match(t) for t in times)):
        raise ValueError(f"Choose {p['times_per_day']} reminder time(s) like 08:00.")
    db.execute("UPDATE med_plans SET reminder_times=?, reminders_on=? WHERE id=?",
               (json.dumps(sorted(times)), 1 if enabled else 0, plan_id))


def set_dose(db, patient_id, plan_id, day, slot, taken):
    p = _plan(db, patient_id, plan_id)
    if not p:
        raise LookupError("Medicine not found.")
    try:
        d = date.fromisoformat(day)
    except (TypeError, ValueError):
        raise ValueError("Invalid day.")
    start = date.fromisoformat(p["start_date"])
    if not (start <= d <= start + timedelta(days=p["duration_days"] - 1)):
        raise ValueError("That day is outside this course.")
    if d > datetime.now(timezone.utc).date() + timedelta(days=1):
        raise ValueError("You can't mark a future day.")
    if not isinstance(slot, int) or not (0 <= slot < p["times_per_day"]):
        raise ValueError("Invalid dose.")
    if taken:
        db.execute("INSERT OR IGNORE INTO dose_logs(plan_id,day,slot,taken_at) VALUES (?,?,?,?)",
                   (plan_id, day, slot, datetime.now(timezone.utc).isoformat(timespec="seconds")))
    else:
        db.execute("DELETE FROM dose_logs WHERE plan_id=? AND day=? AND slot=?", (plan_id, day, slot))
