import Database from "better-sqlite3";
import { mkdirSync } from "fs";

// ── Database setup ─────────────────────────────────────────────────────────

const DATA_DIR = process.env.RAILWAY_VOLUME_MOUNT_PATH ?? "./data";
mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(`${DATA_DIR}/cache.sqlite`);
db.pragma("journal_mode = WAL");
db.pragma("synchronous = NORMAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS domain_cache (
    domain     TEXT PRIMARY KEY,
    payload    TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_expires ON domain_cache(expires_at);
`);

// Purge stale rows on startup (keeps the DB from growing unbounded)
db.prepare("DELETE FROM domain_cache WHERE expires_at < ?").run(Date.now());

// ── Persistent cache ───────────────────────────────────────────────────────

export class Cache<T> {
  private ttlMs: number;

  constructor(ttlMs: number) {
    this.ttlMs = ttlMs;
  }

  set(key: string, value: T): void {
    const expires_at = Date.now() + this.ttlMs;
    db.prepare(`
      INSERT INTO domain_cache (domain, payload, expires_at)
      VALUES (?, ?, ?)
      ON CONFLICT(domain) DO UPDATE SET payload = excluded.payload, expires_at = excluded.expires_at
    `).run(key, JSON.stringify(value), expires_at);
  }

  get(key: string): T | null {
    const row = db.prepare(
      "SELECT payload FROM domain_cache WHERE domain = ? AND expires_at > ?"
    ).get(key, Date.now()) as { payload: string } | undefined;
    if (!row) return null;
    try {
      return JSON.parse(row.payload) as T;
    } catch {
      return null;
    }
  }

  delete(key: string): void {
    db.prepare("DELETE FROM domain_cache WHERE domain = ?").run(key);
  }

  size(): number {
    const row = db.prepare(
      "SELECT COUNT(*) as n FROM domain_cache WHERE expires_at > ?"
    ).get(Date.now()) as { n: number };
    return row.n;
  }
}
