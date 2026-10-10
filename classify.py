"""Auto-tagging: every record gets a category and a sensitivity tier when it is issued, so the
patient never has to judge what is sensitive.

  Tier 1  routine: vitals, routine labs, prescriptions, general check-ups
  Tier 2  specialist: imaging, surgery, chronic-condition consultations
  Tier 3  restricted: mental health, sexual & reproductive health (needs explicit opt-in + PIN)
"""
import re

CATEGORIES = {
    "general": {"label": "General health", "tier3": False},
    "diabetes": {"label": "Diabetes", "tier3": False},
    "cardiology": {"label": "Heart & blood pressure", "tier3": False},
    "respiratory": {"label": "Lungs & asthma", "tier3": False},
    "orthopedics": {"label": "Bones & joints", "tier3": False},
    "mental_health": {"label": "Mental health", "tier3": True},
    "sexual_reproductive": {"label": "Sexual & reproductive health", "tier3": True},
}
SENSITIVE = {k for k, v in CATEGORIES.items() if v["tier3"]}
RECORD_TYPES = ["consultation", "prescription", "lab", "imaging", "vitals", "procedure"]

# Regex prefixes (matched at a word start). Short, risky ones end with \b.
KEYWORDS = {
    "sexual_reproductive": ["pregnan", "contracept", "gynae", "gyneco", "menstru", "fertil", "pcos",
                            r"hiv\b", r"std\b", r"sti\b", "sexual", "antenatal", "prenatal", r"ivf\b"],
    "mental_health": ["depress", "anxiety", "psychiat", "psycholog", "sertraline", "escitalopram",
                      "fluoxetine", "paroxetine", "bipolar", "insomnia", "panic", "counsel",
                      "schizo", "mental", r"cbt\b", "therapy session"],
    "diabetes": ["diabet", "hba1c", "glucose", "insulin", "metformin", "glimepiride", "sitagliptin",
                 "glycated", "glycosylated", r"fbs\b", r"ppbs\b", "hyperglyc", "retinopathy"],
    "cardiology": ["hypertens", "blood pressure", "cardi", "heart", r"ecg\b", r"echo\b", "amlodipine",
                   "telmisartan", "losartan", "atenolol", "metoprolol", "statin", "cholesterol",
                   "lipid", "angina", "aspirin", "clopidogrel", "troponin", "palpitation",
                   "propranolol"],
    "respiratory": ["asthma", "copd", "inhaler", "salbutamol", "budesonide", "montelukast",
                    "spirometry", "bronch", "wheez", "pulmonary", "peak flow", "pneumon"],
    "orthopedics": ["fracture", r"x-?ray\b", "knee", "joint", "arthritis", "osteo", "orthop", "spine",
                    "ligament", r"acl\b", "diclofenac", "physiotherapy", "sprain", "shoulder", r"hip\b"],
}
_PATTERNS = {cat: re.compile(r"\b(?:" + "|".join(words) + ")", re.I) for cat, words in KEYWORDS.items()}
_PRIORITY = list(KEYWORDS)  # ties are won by the more privacy-sensitive category


def _flatten(value):
    if isinstance(value, dict):
        for v in value.values():
            yield from _flatten(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _flatten(v)
    elif value is not None:
        yield str(value)


def detect_category(title: str, data) -> str:
    text = " ".join([title or "", *_flatten(data)])
    scores = {cat: len(p.findall(text)) for cat, p in _PATTERNS.items()}
    best = max(_PRIORITY, key=lambda c: (scores[c], -_PRIORITY.index(c)))
    return best if scores[best] else "general"


def classify(record_type: str, title: str, data, override=None, restricted=False):
    """Returns (category, tier)."""
    category = override if override in CATEGORIES else detect_category(title, data)
    if category in SENSITIVE or restricted:
        tier = 3
    elif record_type in ("imaging", "procedure") or (record_type == "consultation" and category != "general"):
        tier = 2
    else:
        tier = 1
    return category, tier
