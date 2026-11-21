-- Migration 1: fresh Wire v2 schema (PRAGMA user_version = 1).
CREATE TABLE IF NOT EXISTS owner (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), identity TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS owner_preferences (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), time_zone TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS contacts (id TEXT PRIMARY KEY, card TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sharing_rules (
  peer TEXT NOT NULL REFERENCES contacts(id), activity TEXT NOT NULL, original_start TEXT NOT NULL,
  duration INTEGER NOT NULL, slots TEXT NOT NULL,
  closed_at TEXT, close_reason TEXT
);
CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, scopes TEXT NOT NULL, expires INTEGER NOT NULL, created_at TEXT NOT NULL, closed_at TEXT, close_reason TEXT, verbs TEXT NOT NULL, types TEXT NOT NULL, peers TEXT
);
CREATE TABLE IF NOT EXISTS events (
  row_id INTEGER PRIMARY KEY, actor TEXT NOT NULL, recipient TEXT NOT NULL, event_id TEXT NOT NULL,
  topic TEXT NOT NULL, parent TEXT, body TEXT NOT NULL, digest TEXT NOT NULL, stored_at TEXT NOT NULL,
  jws TEXT, typ TEXT, direction TEXT NOT NULL, grant_id TEXT, grant_actor TEXT, receipt TEXT,
  outcome TEXT, outcome_at TEXT, outcome_code TEXT, rejection_row INTEGER, apply_count INTEGER NOT NULL DEFAULT 0,
  retain_until TEXT,
  UNIQUE(actor, recipient, event_id)
);
CREATE INDEX IF NOT EXISTS topic_history ON events(topic, row_id);
CREATE INDEX IF NOT EXISTS topic_parent ON events(topic, parent, actor);
CREATE TABLE IF NOT EXISTS threads (id TEXT PRIMARY KEY, state TEXT NOT NULL, last_row INTEGER NOT NULL UNIQUE);
CREATE INDEX IF NOT EXISTS occurrence_lookup ON threads(
  json_extract(state,'$.activity'), json_extract(state,'$.originalStart'), json_extract(state,'$.durationMinutes')
);
CREATE TABLE IF NOT EXISTS request_keys (id TEXT PRIMARY KEY, params TEXT NOT NULL, topic TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS handoff_approvals (
  peer TEXT NOT NULL REFERENCES contacts(id), topic TEXT NOT NULL, action TEXT NOT NULL, request_key TEXT,
  created_at TEXT NOT NULL, closed_at TEXT, close_reason TEXT, used_by TEXT
);
CREATE TABLE IF NOT EXISTS outbox (
  event_row INTEGER PRIMARY KEY REFERENCES events(row_id), status TEXT NOT NULL DEFAULT 'queued',
  attempts INTEGER NOT NULL DEFAULT 0, next_at INTEGER NOT NULL DEFAULT 0, error TEXT, receipt TEXT, backoff_ms INTEGER NOT NULL DEFAULT 0, refused_code TEXT, refusal_row INTEGER
);
CREATE INDEX IF NOT EXISTS pending_delivery ON outbox(status, next_at, event_row);
CREATE TABLE IF NOT EXISTS redeliveries (
  row_id INTEGER PRIMARY KEY, event_row INTEGER NOT NULL REFERENCES events(row_id), requested_at TEXT NOT NULL,
  prior_error TEXT NOT NULL, prior_attempts INTEGER NOT NULL
);

CREATE UNIQUE INDEX active_approval ON handoff_approvals(peer,topic,action) WHERE closed_at IS NULL;
CREATE UNIQUE INDEX active_sharing ON sharing_rules(peer,activity,original_start,duration) WHERE closed_at IS NULL;
CREATE TABLE attempts (
  id INTEGER PRIMARY KEY, event_row INTEGER NOT NULL REFERENCES events(row_id), at TEXT NOT NULL,
  result TEXT NOT NULL, code TEXT, status INTEGER, headers TEXT, body TEXT
);
