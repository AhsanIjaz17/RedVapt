/**
 * db.js — RedVapt SQLite Intelligence Store
 *
 * Security: All inserts use parameterized statements (no string interpolation).
 * Each scan run creates a fresh in-memory DB — no cross-scan data leakage.
 *
 * Schema v2: adds js_secrets, parameters, dns_resolved, waf_info on live_hosts
 */

import Database from 'better-sqlite3';

export function createScanDB() {
  // In-memory DB per scan run — isolated, no file system residue
  const db = new Database(':memory:');

  // Enable WAL + foreign keys
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  db.exec(`
    CREATE TABLE IF NOT EXISTS subdomains (
      id        INTEGER PRIMARY KEY AUTOINCREMENT,
      subdomain TEXT NOT NULL,
      source    TEXT NOT NULL,
      resolves  INTEGER DEFAULT 0,
      ip        TEXT,
      UNIQUE(subdomain)
    );

    CREATE TABLE IF NOT EXISTS live_hosts (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      url          TEXT NOT NULL UNIQUE,
      status_code  INTEGER,
      title        TEXT,
      technologies TEXT,
      server       TEXT,
      ip           TEXT,
      cdn          INTEGER DEFAULT 0,
      waf          TEXT
    );

    CREATE TABLE IF NOT EXISTS services (
      id      INTEGER PRIMARY KEY AUTOINCREMENT,
      host    TEXT NOT NULL,
      port    INTEGER NOT NULL,
      state   TEXT,
      service TEXT,
      version TEXT,
      UNIQUE(host, port)
    );

    CREATE TABLE IF NOT EXISTS endpoints (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      url             TEXT NOT NULL UNIQUE,
      has_params      INTEGER DEFAULT 0,
      path_depth      INTEGER DEFAULT 0,
      sensitivity_tag TEXT,
      source          TEXT DEFAULT 'gau'
    );

    CREATE TABLE IF NOT EXISTS js_files (
      id                INTEGER PRIMARY KEY AUTOINCREMENT,
      url               TEXT NOT NULL UNIQUE,
      source            TEXT DEFAULT 'crawler',
      category          TEXT,
      severity          TEXT,
      reason            TEXT,
      recommended_tests TEXT
    );

    CREATE TABLE IF NOT EXISTS js_secrets (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      js_url      TEXT NOT NULL,
      secret_type TEXT NOT NULL,
      value       TEXT NOT NULL,
      raw         TEXT,
      UNIQUE(js_url, value)
    );

    CREATE TABLE IF NOT EXISTS js_endpoints (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      js_url          TEXT NOT NULL,
      endpoint        TEXT NOT NULL,
      is_relative     INTEGER DEFAULT 0,
      sensitivity_tag TEXT,
      UNIQUE(js_url, endpoint)
    );

    CREATE TABLE IF NOT EXISTS parameters (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      url         TEXT NOT NULL UNIQUE,
      params      TEXT NOT NULL,
      param_count INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS findings (
      id        INTEGER PRIMARY KEY AUTOINCREMENT,
      category  TEXT NOT NULL,
      severity  TEXT NOT NULL,
      detail    TEXT NOT NULL,
      source_tool TEXT
    );

    CREATE TABLE IF NOT EXISTS technologies (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      name       TEXT NOT NULL UNIQUE,
      category   TEXT,
      version    TEXT,
      confidence INTEGER DEFAULT 0,
      website    TEXT
    );

    CREATE TABLE IF NOT EXISTS forms (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      action        TEXT NOT NULL,
      method        TEXT DEFAULT 'GET',
      inputs        TEXT NOT NULL, -- JSON string of input names
      is_high_value INTEGER DEFAULT 0,
      UNIQUE(action, inputs)
    );
  `);

  // ── Prepared statements ─────────────────────────────────────────────────────

  const stmts = {
    insertSubdomain: db.prepare(
      `INSERT OR IGNORE INTO subdomains (subdomain, source) VALUES (?, ?)`
    ),
    updateSubdomainDns: db.prepare(
      `UPDATE subdomains SET resolves=?, ip=? WHERE subdomain=?`
    ),
    insertLiveHost: db.prepare(
      `INSERT OR IGNORE INTO live_hosts
         (url, status_code, title, technologies, server, ip, cdn, waf)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ),
    insertService: db.prepare(
      `INSERT OR IGNORE INTO services (host, port, state, service, version)
       VALUES (?, ?, ?, ?, ?)`
    ),
    insertEndpoint: db.prepare(
      `INSERT OR IGNORE INTO endpoints (url, has_params, path_depth, sensitivity_tag, source)
       VALUES (?, ?, ?, ?, ?)`
    ),
    insertJsFile: db.prepare(
      `INSERT OR IGNORE INTO js_files (url, source) VALUES (?, ?)`
    ),
    updateJsClassification: db.prepare(
      `UPDATE js_files SET category=?, severity=?, reason=?, recommended_tests=? WHERE url=?`
    ),
    insertJsSecret: db.prepare(
      `INSERT OR IGNORE INTO js_secrets (js_url, secret_type, value, raw)
       VALUES (?, ?, ?, ?)`
    ),
    insertJsEndpoint: db.prepare(
      `INSERT OR IGNORE INTO js_endpoints (js_url, endpoint, is_relative, sensitivity_tag)
       VALUES (?, ?, ?, ?)`
    ),
    insertParameter: db.prepare(
      `INSERT OR IGNORE INTO parameters (url, params, param_count) VALUES (?, ?, ?)`
    ),
    insertFinding: db.prepare(
      `INSERT INTO findings (category, severity, detail, source_tool)
       VALUES (?, ?, ?, ?)`
    ),
    insertTechnology: db.prepare(
      `INSERT OR REPLACE INTO technologies (name, category, version, confidence, website)
       VALUES (?, ?, ?, ?, ?)`
    ),
    insertForm: db.prepare(
      `INSERT OR IGNORE INTO forms (action, method, inputs, is_high_value)
       VALUES (?, ?, ?, ?)`
    ),
  };

  // ── Batch insert helpers ────────────────────────────────────────────────────

  const insertSubdomains = db.transaction((rows) => {
    for (const r of rows) stmts.insertSubdomain.run(r.subdomain, r.source);
  });

  const updateDnsResolved = db.transaction((rows) => {
    for (const r of rows) stmts.updateSubdomainDns.run(r.resolves ? 1 : 0, r.ip || null, r.subdomain);
  });

  const insertLiveHosts = db.transaction((rows) => {
    for (const r of rows)
      stmts.insertLiveHost.run(
        r.url, r.status_code, r.title, r.technologies, r.server,
        r.ip, r.cdn ? 1 : 0, r.waf || null
      );
  });

  const insertServices = db.transaction((rows) => {
    for (const r of rows)
      stmts.insertService.run(r.host, r.port, r.state, r.service, r.version);
  });

  const insertEndpoints = db.transaction((rows, source = 'gau') => {
    for (const r of rows)
      stmts.insertEndpoint.run(r.url, r.has_params ? 1 : 0, r.path_depth, r.sensitivity_tag, r.source || source);
  });

  const insertJsFiles = db.transaction((rows) => {
    for (const r of rows) stmts.insertJsFile.run(r.url, r.source || 'crawler');
  });

  const updateJsClassifications = db.transaction((classifiedFiles) => {
    for (const f of classifiedFiles) {
      stmts.updateJsClassification.run(
        f.category, f.severity, f.reason,
        JSON.stringify(f.recommended_tests || []),
        f.url
      );
    }
  });

  const insertJsSecrets = db.transaction((jsUrl, rows) => {
    for (const r of rows) stmts.insertJsSecret.run(jsUrl, r.secret_type, r.value, r.raw || '');
  });

  const insertJsEndpoints = db.transaction((jsUrl, rows) => {
    for (const r of rows)
      stmts.insertJsEndpoint.run(jsUrl, r.url, r.is_relative ? 1 : 0, r.sensitivity_tag || null);
  });

  const insertParameters = db.transaction((rows) => {
    for (const r of rows)
      stmts.insertParameter.run(r.url, r.params, r.param_count);
  });

  const insertFindings = db.transaction((rows) => {
    for (const r of rows)
      stmts.insertFinding.run(r.category, r.severity, r.detail, r.source_tool);
  });

  const insertTechnologies = db.transaction((rows) => {
    for (const r of rows)
      stmts.insertTechnology.run(r.name, r.category, r.version, r.confidence, r.website);
  });

  const insertForms = db.transaction((rows) => {
    for (const r of rows)
      stmts.insertForm.run(r.action, r.method || 'GET', JSON.stringify(r.inputs), r.is_high_value ? 1 : 0);
  });

  // ── Query helpers ───────────────────────────────────────────────────────────

  const queries = {
    countSubdomains: () => db.prepare(`SELECT COUNT(*) as n FROM subdomains`).get().n,
    allSubdomains: () => db.prepare(`SELECT * FROM subdomains ORDER BY resolves DESC`).all(),
    resolvedSubdomains: () => db.prepare(`SELECT subdomain, ip FROM subdomains WHERE resolves=1`).all(),
    allLiveHosts: () => db.prepare(`SELECT * FROM live_hosts ORDER BY status_code`).all(),
    allServices: () => db.prepare(`SELECT * FROM services WHERE state='open' ORDER BY port`).all(),
    allEndpoints: () => db.prepare(
      `SELECT * FROM endpoints ORDER BY has_params DESC, path_depth DESC LIMIT 100`
    ).all(),
    allJsFiles: () => db.prepare(`SELECT * FROM js_files`).all(),
    allJsSecrets: () => db.prepare(`SELECT * FROM js_secrets LIMIT 50`).all(),
    classifiedJsFiles: () => db.prepare(`SELECT * FROM js_files WHERE category IS NOT NULL ORDER BY
      CASE severity WHEN '🔴' THEN 1 WHEN '🟠' THEN 2 WHEN '🟡' THEN 3 ELSE 4 END`).all(),
    highValueJsFiles: () => db.prepare(`SELECT * FROM js_files WHERE severity IN ('🔴','🟠')`).all(),
    jsClassificationSummary: () => {
      const rows = db.prepare(`SELECT category, severity, COUNT(*) as count FROM js_files WHERE category IS NOT NULL GROUP BY category, severity`).all();
      const summary = { total: 0, ignored: 0, medium_value: 0, high_value: 0 };
      for (const r of rows) {
        summary.total += r.count;
        if (r.severity === '⚪') summary.ignored += r.count;
        else if (r.severity === '🟡') summary.medium_value += r.count;
        else summary.high_value += r.count;
      }
      return summary;
    },
    allJsEndpoints: () => db.prepare(
      `SELECT * FROM js_endpoints ORDER BY sensitivity_tag DESC LIMIT 80`
    ).all(),
    allParameters: () => db.prepare(
      `SELECT * FROM parameters ORDER BY param_count DESC LIMIT 60`
    ).all(),
    allFindings: () => db.prepare(`SELECT * FROM findings ORDER BY
      CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END`
    ).all(),
    countLiveHosts: () => db.prepare(`SELECT COUNT(*) as n FROM live_hosts`).get().n,
    countServices: () => db.prepare(`SELECT COUNT(*) as n FROM services WHERE state='open'`).get().n,
    countEndpoints: () => db.prepare(`SELECT COUNT(*) as n FROM endpoints`).get().n,
    countJsFiles: () => db.prepare(`SELECT COUNT(*) as n FROM js_files`).get().n,
    countJsSecrets: () => db.prepare(`SELECT COUNT(*) as n FROM js_secrets`).get().n,
    countParameters: () => db.prepare(`SELECT COUNT(*) as n FROM parameters`).get().n,
    allTechnologies: () => db.prepare(`SELECT * FROM technologies ORDER BY confidence DESC`).all(),
    countTechnologies: () => db.prepare(`SELECT COUNT(*) as n FROM technologies`).get().n,
    allForms: () => db.prepare(`SELECT * FROM forms ORDER BY is_high_value DESC`).all(),
    countForms: () => db.prepare(`SELECT COUNT(*) as n FROM forms`).get().n,
  };

  return {
    db,
    insertSubdomains,
    updateDnsResolved,
    insertLiveHosts,
    insertServices,
    insertEndpoints,
    insertJsFiles,
    updateJsClassifications,
    insertJsSecrets,
    insertJsEndpoints,
    insertParameters,
    insertFindings,
    insertTechnologies,
    insertForms,
    queries,
  };
}
