"""SQLite storage. One connection per request; routes commit explicitly."""
import sqlite3

from flask import g

from .config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS hospitals(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL,
  public_key TEXT NOT NULL,          -- Ed25519 public key (verifies signatures)
  signing_key_enc TEXT NOT NULL      -- Ed25519 private key, wrapped with the master key
);
CREATE TABLE IF NOT EXISTS patients(
  id TEXT PRIMARY KEY, health_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL, dob TEXT NOT NULL,
  sex TEXT NOT NULL, blood_group TEXT NOT NULL,
  data_key_enc TEXT NOT NULL         -- per-patient AES-256 data key, wrapped with the master key
);
CREATE TABLE IF NOT EXISTS users(
  id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, pw_hash TEXT NOT NULL,
  role TEXT NOT NULL, ref_id TEXT NOT NULL, display TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS records(
  id TEXT PRIMARY KEY,
  patient_id TEXT NOT NULL REFERENCES patients(id),
  hospital_id TEXT NOT NULL REFERENCES hospitals(id),
  record_type TEXT NOT NULL, category TEXT NOT NULL, tier INTEGER NOT NULL,
  record_date TEXT NOT NULL, created_at TEXT NOT NULL,
  ciphertext TEXT NOT NULL,          -- AES-256-GCM(title + clinical data)
  signature TEXT NOT NULL            -- Ed25519 over metadata + hash of ciphertext
);
CREATE INDEX IF NOT EXISTS idx_records_patient ON records(patient_id, record_date);
CREATE TABLE IF NOT EXISTS shares(
  id TEXT PRIMARY KEY, patient_id TEXT NOT NULL REFERENCES patients(id),
  label TEXT NOT NULL, scope TEXT NOT NULL, pin_hash TEXT,
  created_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT,
  views INTEGER NOT NULL DEFAULT 0, last_viewed_at TEXT, pin_failures INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS med_plans(
  id TEXT PRIMARY KEY, patient_id TEXT NOT NULL REFERENCES patients(id),
  record_id TEXT NOT NULL REFERENCES records(id), med_idx INTEGER NOT NULL,
  start_date TEXT NOT NULL, duration_days INTEGER NOT NULL, times_per_day INTEGER NOT NULL,
  reminder_times TEXT NOT NULL,      -- JSON list chosen by the patient, e.g. ["08:00","20:00"]
  reminders_on INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS dose_logs(
  plan_id TEXT NOT NULL REFERENCES med_plans(id) ON DELETE CASCADE,
  day TEXT NOT NULL, slot INTEGER NOT NULL, taken_at TEXT NOT NULL,
  PRIMARY KEY(plan_id, day, slot)
);
"""
TABLES = ["dose_logs", "med_plans", "shares", "records", "users", "patients", "hospitals"]


def connect():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA journal_mode=WAL")
    return con


def get_db():
    if "db" not in g:
        g.db = connect()
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()  # anything not committed is rolled back


def init_db():
    con = connect()
    con.executescript(SCHEMA)
    con.commit()
    con.close()
