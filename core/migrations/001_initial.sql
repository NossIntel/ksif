CREATE TABLE operations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    module TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    operator TEXT NOT NULL,
    intrusiveness TEXT NOT NULL,
    command TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'running',
    error TEXT,
    summary TEXT,
    raw_output_path TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT
);

CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    operator TEXT NOT NULL,
    event TEXT NOT NULL,
    detail_json TEXT NOT NULL
);

CREATE TABLE hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT NOT NULL UNIQUE,
    family TEXT NOT NULL,
    mac TEXT,
    vendor TEXT,
    hostname TEXT,
    os_guess TEXT,
    os_accuracy INTEGER,
    device_type TEXT,
    state TEXT NOT NULL DEFAULT 'up',
    hops_json TEXT NOT NULL DEFAULT '[]',
    first_seen_op INTEGER REFERENCES operations(id),
    last_seen_op INTEGER REFERENCES operations(id),
    updated_at TEXT NOT NULL
);

CREATE TABLE host_sightings (
    op_id INTEGER NOT NULL REFERENCES operations(id),
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    PRIMARY KEY (op_id, host_id)
);

CREATE TABLE ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    number INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    state TEXT NOT NULL,
    service TEXT,
    product TEXT,
    version TEXT,
    op_id INTEGER REFERENCES operations(id),
    UNIQUE (host_id, number, protocol)
);

CREATE TABLE reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    op_id INTEGER REFERENCES operations(id),
    format TEXT NOT NULL,
    path TEXT NOT NULL,
    created_at TEXT NOT NULL
);
