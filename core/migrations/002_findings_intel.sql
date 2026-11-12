CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    op_id INTEGER REFERENCES operations(id),
    module TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    target TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT '',
    recommendation TEXT NOT NULL DEFAULT '',
    reference TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE osint_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    op_id INTEGER REFERENCES operations(id),
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE (kind, name, value)
);

CREATE TABLE wifi_networks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    op_id INTEGER REFERENCES operations(id),
    bssid TEXT NOT NULL UNIQUE,
    ssid TEXT NOT NULL DEFAULT '',
    channel INTEGER,
    band TEXT NOT NULL DEFAULT '',
    security TEXT NOT NULL DEFAULT '',
    signal INTEGER,
    owned INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);

CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    op_id INTEGER REFERENCES operations(id),
    cve_id TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '',
    port INTEGER,
    product TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    cvss REAL,
    severity TEXT NOT NULL DEFAULT 'unknown',
    epss REAL,
    kev INTEGER NOT NULL DEFAULT 0,
    summary TEXT NOT NULL DEFAULT '',
    recommendation TEXT NOT NULL DEFAULT '',
    priority REAL NOT NULL DEFAULT 0,
    source TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    UNIQUE (cve_id, host, port, product)
);
