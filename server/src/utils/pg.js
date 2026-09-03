import pg from 'pg';
import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';
import config from '../config/env.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const { Pool } = pg;

// DB Choice Logic
const isPostgres = config.DB_TYPE === 'postgres';
let pool = null;
let sqlite = null;

if (isPostgres) {
  pool = new Pool({
    connectionString: config.DATABASE_URL
  });
} else {
  // Use persistent sqlite file in server root
  const dbPath = path.join(__dirname, '../../redvapt.db');
  sqlite = new Database(dbPath);
  sqlite.pragma('journal_mode = WAL');
}

export async function initPostgres() {
  if (isPostgres) {
    const client = await pool.connect();
    try {
      await client.query(`
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          role TEXT DEFAULT 'user',
          is_verified BOOLEAN DEFAULT FALSE,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS workspaces (
          id SERIAL PRIMARY KEY,
          name TEXT NOT NULL,
          owner_user_id INTEGER REFERENCES users(id),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS workspace_members (
          id SERIAL PRIMARY KEY,
          workspace_id INTEGER REFERENCES workspaces(id),
          user_id INTEGER REFERENCES users(id),
          role TEXT DEFAULT 'member', 
          joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(workspace_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS scans (
          id SERIAL PRIMARY KEY,
          workspace_id INTEGER REFERENCES workspaces(id),
          target TEXT NOT NULL,
          status TEXT DEFAULT 'pending',
          created_by_user_id INTEGER REFERENCES users(id),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS findings (
          id SERIAL PRIMARY KEY,
          scan_id INTEGER REFERENCES scans(id),
          workspace_id INTEGER REFERENCES workspaces(id),
          category TEXT NOT NULL,
          severity TEXT NOT NULL,
          detail TEXT NOT NULL,
          source_tool TEXT,
          evidence JSONB,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS reports (
          id SERIAL PRIMARY KEY,
          scan_id INTEGER REFERENCES scans(id),
          workspace_id INTEGER REFERENCES workspaces(id),
          report_path TEXT,
          report_json JSONB,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);
    } finally {
      client.release();
    }
  } else {
    // SQLite Schema
    sqlite.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        is_verified BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS workspaces (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        owner_user_id INTEGER REFERENCES users(id),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS workspace_members (
        workspace_id INTEGER REFERENCES workspaces(id),
        user_id INTEGER REFERENCES users(id),
        role TEXT DEFAULT 'member', 
        joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (workspace_id, user_id)
      );

      CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        workspace_id INTEGER REFERENCES workspaces(id),
        target TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        created_by_user_id INTEGER REFERENCES users(id),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER REFERENCES scans(id),
        workspace_id INTEGER REFERENCES workspaces(id),
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        detail TEXT NOT NULL,
        source_tool TEXT,
        evidence TEXT, -- JSON in SQLite
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);
  }
}

// Unified query interface
export const query = async (text, params) => {
  if (isPostgres) {
    return await pool.query(text, params);
  } else {
    let sqliteSql = text.replaceAll(/\$(\d+)/g, '?');

    // Strip RETURNING clause for SQLite compatibility (some versions don't support it)
    const returningMatch = sqliteSql.match(/RETURNING\s+.+$/i);
    if (returningMatch) {
      sqliteSql = sqliteSql.substring(0, returningMatch.index).trim();
    }

    if (sqliteSql.trim().toUpperCase() === 'BEGIN') return sqlite.exec('BEGIN');
    if (sqliteSql.trim().toUpperCase() === 'COMMIT') return sqlite.exec('COMMIT');
    if (sqliteSql.trim().toUpperCase() === 'ROLLBACK') return sqlite.exec('ROLLBACK');

    const statement = sqlite.prepare(sqliteSql);

    if (text.trim().toLowerCase().startsWith('select')) {
      const rows = statement.all(params || []);
      return { rows, rowCount: rows.length };
    } else {
      const info = statement.run(params || []);
      const rows = [];
      // If we stripped a returning clause, simulate it with lastInsertRowid
      if (returningMatch) {
        rows.push({ id: info.lastInsertRowid });
      }
      return { rowCount: info.changes, rows, insertId: info.lastInsertRowid };
    }
  }
};

// Connect fallback for transactions
export const connect = async () => {
  if (isPostgres) return await pool.connect();
  // For SQLite, return the pool/sqlite object itself with a mock release
  return {
    query,
    release: () => { }
  };
};

export default { query, connect, initPostgres, isPostgres, pool, sqlite };
