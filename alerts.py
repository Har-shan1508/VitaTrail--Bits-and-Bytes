"""Smart redundancy & conflict detector.

Because records from every provider land in one place, we can spot problems no single provider
can see: the same test repeated within 30 days, interacting or duplicated medicines prescribed by
different doctors, and a new medicine that clashes with a documented allergy or condition.

The interaction table is a small DEMO ruleset, not clinical advice. In production this would be
backed by a licensed drug database.
"""
import itertools
import re
from datetime import date, timedelta

DUP_DAYS = 30
SEVERITY = {"high": 0, "moderate": 1, "info": 2}

_SKIP = {"tab", "tablet", "cap", "capsule", "inj", "injection", "syp", "syrup", "oral", "inhaler", "the"}
ALIASES = {"acetaminophen": "paracetamol", "ecosprin": "aspirin", "voveran": "diclofenac",
           "brufen": "ibuprofen", "glycomet": "metformin", "norvasc": "amlodipine",
           "lipitor": "atorvastatin", "ventolin": "salbutamol", "zoloft": "sertraline",
           "inderal": "propranolol", "augmentin": "amoxicillin"}
CLASSES = {
    "diclofenac": "nsaid", "ibuprofen": "nsaid", "naproxen": "nsaid", "ketorolac": "nsaid",
    "etoricoxib": "nsaid", "aceclofenac": "nsaid",
    "aspirin": "antiplatelet", "clopidogrel": "antiplatelet",
    "warfarin": "anticoagulant", "rivaroxaban": "anticoagulant", "apixaban": "anticoagulant",
    "atorvastatin": "statin", "simvastatin": "statin", "rosuvastatin": "statin",
    "amlodipine": "ccb", "telmisartan": "arb", "losartan": "arb",
    "enalapril": "acei", "ramipril": "acei", "lisinopril": "acei",
    "atenolol": "beta_blocker", "metoprolol": "beta_blocker", "propranolol": "beta_blocker",
    "bisoprolol": "beta_blocker",
    "sertraline": "ssri", "escitalopram": "ssri", "fluoxetine": "ssri", "paroxetine": "ssri",
    "salbutamol": "bronchodilator", "clarithromycin": "macrolide", "erythromycin": "macrolide",
    "isosorbide": "nitrate", "nitroglycerin": "nitrate",
    "furosemide": "diuretic", "hydrochlorothiazide": "diuretic", "spironolactone": "diuretic",
    "amoxicillin": "penicillin", "ampicillin": "penicillin", "penicillin": "penicillin",
    "cloxacillin": "penicillin",
}
SAME_CLASS_WARN = {"nsaid", "statin", "acei", "arb", "beta_blocker", "ssri", "ccb"}

# (ids on one side, ids on the other side, severity, plain-language message)
RULES = [
    ({"nsaid"}, {"antiplatelet", "anticoagulant"}, "high",
     "Pain-relief tablets (NSAIDs) taken with aspirin or blood thinners raise the risk of stomach "
     "bleeding, and can weaken aspirin's heart protection."),
    ({"antiplatelet"}, {"anticoagulant"}, "high", "Aspirin or clopidogrel with a blood thinner greatly raises bleeding risk."),
    ({"ssri"}, {"tramadol"}, "high", "Can cause serotonin syndrome (agitation, fever, fast heartbeat)."),
    ({"beta_blocker"}, {"bronchodilator"}, "high", "Beta-blockers can block salbutamol and trigger breathing trouble."),
    ({"acei", "arb"}, {"spironolactone"}, "high", "Can push potassium to dangerous levels."),
    ({"sildenafil"}, {"nitrate"}, "high", "Can cause a sudden, severe drop in blood pressure."),
    ({"macrolide"}, {"statin"}, "high", "Raises statin levels and the risk of muscle damage."),
    ({"ssri"}, {"nsaid", "antiplatelet", "anticoagulant"}, "moderate",
     "Antidepressants of this type add to the bleeding risk of pain-relief tablets, aspirin and blood thinners."),
    ({"nsaid"}, {"acei", "arb", "ccb", "beta_blocker", "diuretic"}, "moderate",
     "Pain-relief tablets (NSAIDs) can raise blood pressure and blunt BP medicines; kidneys may be strained."),
    ({"amlodipine"}, {"simvastatin"}, "moderate", "Simvastatin should be capped at 20 mg a day with amlodipine."),
]
ALLERGY_IDS = {"penicillin": {"penicillin"}, "sulfa": {"sulfamethoxazole", "cotrimoxazole", "sulfasalazine"},
               "aspirin": {"aspirin"}, "nsaid": {"nsaid"}, "ibuprofen": {"ibuprofen"}}
CONDITION_RULES = [
    ("asthma", {"beta_blocker"}, "high", "Beta-blockers can trigger asthma attacks."),
    ("kidney|renal|ckd", {"nsaid"}, "high", "NSAIDs can harm kidneys that are already weak."),
]
TEST_ALIASES = {"glycatedhemoglobin": "hba1c", "glycosylatedhemoglobin": "hba1c", "a1c": "hba1c",
                "completebloodcount": "cbc", "fbs": "fastingglucose", "fastingbloodsugar": "fastingglucose",
                "fastingplasmaglucose": "fastingglucose", "ldl": "ldlcholesterol", "hdl": "hdlcholesterol",
                "cholesterol": "totalcholesterol"}


def norm_drug(name: str) -> str:
    for word in re.findall(r"[a-z]+", (name or "").lower()):
        if word not in _SKIP:
            return ALIASES.get(word, word)
    return ""


def norm_test(name: str) -> str:
    key = re.sub(r"[^a-z0-9]", "", (name or "").lower())
    return TEST_ALIASES.get(key, key)


def _ids(med):
    return {med["norm"], CLASSES.get(med["norm"], "")} - {""}


def _d(value):
    return value if isinstance(value, date) else date.fromisoformat(value)


# ---- turn decrypted records into a plain "state" -----------------------------------------
def build_state(records, with_restricted=True):
    st = {"meds": [], "tests": [], "allergies": [], "conditions": []}
    seen_a, seen_c = set(), set()
    for r in records:
        d, rd = r["data"], _d(r["date"])
        src = {"hospital": r["hospital"]["name"], "tier": r["tier"], "record_id": r["id"]}
        if r["type"] == "prescription":
            for m in d.get("medications", []):
                st["meds"].append({**src, "name": m["name"], "norm": norm_drug(m["name"]), "dose": m.get("dose", ""),
                                   "times": m.get("times", 1), "instructions": m.get("instructions", ""),
                                   "start": rd, "end": rd + timedelta(days=int(m.get("days") or 1) - 1)})
        elif r["type"] == "lab":
            for t in d.get("tests", []):
                value = f'{t.get("value", "")} {t.get("unit", "")}'.strip()
                st["tests"].append({**src, "name": t["name"], "norm": norm_test(t["name"]), "date": rd, "value": value})
        elif r["type"] == "consultation" and (with_restricted or r["tier"] < 3):
            for a in re.split(r"[;,\n]", d.get("allergies", "")):
                if a.strip() and a.strip().lower() not in seen_a:
                    seen_a.add(a.strip().lower())
                    st["allergies"].append(a.strip())
            diag = (d.get("diagnosis") or "").strip()
            if d.get("chronic") and diag and diag.lower() not in seen_c:
                seen_c.add(diag.lower())
                st["conditions"].append(diag)
    return st


def build_summary(state, today):
    today = _d(today)
    meds = [m for m in state["meds"] if m["start"] <= today <= m["end"]]
    return {
        "allergies": state["allergies"],
        "conditions": state["conditions"],
        "active_meds": [{"name": m["name"], "dose": m["dose"], "hospital": m["hospital"], "times": m["times"],
                         "instructions": m["instructions"], "until": m["end"].isoformat(), "tier": m["tier"]}
                        for m in sorted(meds, key=lambda m: m["name"].lower())],
    }


# ---- the detector ------------------------------------------------------------------------
def _alert(kind, severity, title, detail, refs=()):
    return {"kind": kind, "severity": severity, "title": title, "detail": detail, "refs": list(refs)}


def evaluate(state, today, new_meds=(), new_tests=(), mask=False):
    """Alerts for the patient's current state. When `new_meds` / `new_tests` are given (a hospital
    about to issue something) only alerts that involve the new items are returned. With `mask`,
    anything coming from a Tier-3 record is described generically so restricted data never leaks."""
    today = _d(today)
    only_new = bool(new_meds or new_tests)
    out = []

    def who(item):  # how to describe an existing item
        if mask and item.get("tier") == 3:
            return "a restricted medication"
        return item["name"]

    active = [m for m in state["meds"] if m["start"] <= today <= m["end"]]
    new = [{"name": n.strip(), "norm": norm_drug(n), "tier": 1, "new": True, "record_id": None, "hospital": "this order"}
           for n in new_meds if n and n.strip()]
    meds = active + new

    # 1) interactions + duplicate therapy between medicines from different prescriptions
    for a, b in itertools.combinations(meds, 2):
        if (only_new and not (a.get("new") or b.get("new"))) or (a["record_id"] and a["record_id"] == b["record_id"]):
            continue
        refs = [m["record_id"] for m in (a, b) if m["record_id"] and not (mask and m["tier"] == 3)]
        pair = f"{who(a)} + {who(b)}"
        if a["norm"] == b["norm"]:
            out.append(_alert("duplicate_therapy", "moderate", f"Same medicine twice: {who(a)}",
                              f"{a['hospital']} and {b['hospital']} have both prescribed it. Check before adding another course.", refs))
            continue
        ia, ib = _ids(a), _ids(b)
        hit = next((r for r in RULES if (ia & r[0] and ib & r[1]) or (ia & r[1] and ib & r[0])), None)
        if hit:
            out.append(_alert("interaction", hit[2], f"Interaction: {pair}", hit[3], refs))
        else:
            same = {CLASSES.get(a["norm"])} & {CLASSES.get(b["norm"])} & SAME_CLASS_WARN
            if same:
                out.append(_alert("duplicate_therapy", "moderate", f"Two medicines of the same type: {pair}",
                                  "These work in the same way. Taking both may be unnecessary or risky.", refs))

    # 2) documented allergies and chronic conditions vs medicines
    for m in meds:
        if only_new and not m.get("new"):
            continue
        ids = _ids(m)
        for allergy in state["allergies"]:
            if any(key in allergy.lower() and ids & drugs for key, drugs in ALLERGY_IDS.items()):
                out.append(_alert("allergy", "high", f"Allergy warning: {who(m)}",
                                  f"The patient has a documented allergy: {allergy}.", [m["record_id"]] if m["record_id"] else []))
        for pattern, classes, severity, text in CONDITION_RULES:
            cond = next((c for c in state["conditions"] if re.search(pattern, c, re.I)), None)
            if cond and ids & classes:
                out.append(_alert("condition", severity, f"{who(m)} with {cond}", text, [m["record_id"]] if m["record_id"] else []))

    # 3) the same test repeated within DUP_DAYS
    by_test = {}
    for t in state["tests"]:
        by_test.setdefault(t["norm"], []).append(t)
    groups = {}
    if new_tests:
        for name in new_tests:
            prev = [t for t in by_test.get(norm_test(name), []) if 0 <= (today - t["date"]).days <= DUP_DAYS]
            if prev:
                p = max(prev, key=lambda t: t["date"])
                groups.setdefault(p["record_id"], {"old": p, "new": None, "names": []})["names"].append(name.strip())
    elif not only_new:
        for lst in by_test.values():
            lst.sort(key=lambda t: t["date"])
            for a, b in zip(lst, lst[1:]):
                if a["record_id"] != b["record_id"] and (b["date"] - a["date"]).days <= DUP_DAYS:
                    groups.setdefault((a["record_id"], b["record_id"]), {"old": a, "new": b, "names": []})["names"].append(a["name"])
    for g in groups.values():
        old, newer, names = g["old"], g["new"], ", ".join(g["names"])
        ago = (today - old["date"]).days
        where = "a restricted provider" if mask and old["tier"] == 3 else old["hospital"]
        if newer:
            gap = (newer["date"] - old["date"]).days
            out.append(_alert("duplicate_test", "moderate", f"Repeated within {gap} days: {names}",
                              f"Done at {old['hospital']} on {old['date']:%d %b} and again at {newer['hospital']} on "
                              f"{newer['date']:%d %b}. Sharing records could have avoided the second test.",
                              [old["record_id"], newer["record_id"]]))
        else:
            result = f" (result: {old['value']})" if old["value"] and not mask else ""
            out.append(_alert("duplicate_test", "moderate", f"Already tested: {names}",
                              f"Done {ago} day{'s' if ago != 1 else ''} ago at {where}{result}. "
                              "Consider using that result instead of repeating the test.", [old["record_id"]]))

    out.sort(key=lambda a: SEVERITY[a["severity"]])
    return out
