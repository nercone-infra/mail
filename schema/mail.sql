CREATE TABLE IF NOT EXISTS domains (
    domain  TEXT    PRIMARY KEY,
    active  BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS accounts (
    username     TEXT    NOT NULL,
    domain       TEXT    NOT NULL REFERENCES domains (domain) ON DELETE CASCADE,
    password     TEXT    NOT NULL,
    quota_bytes  BIGINT  NOT NULL DEFAULT 0,
    active       BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (username, domain)
);

CREATE TABLE IF NOT EXISTS aliases (
    source       TEXT    NOT NULL,
    destination  TEXT    NOT NULL,
    active       BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (source, destination)
);

CREATE INDEX IF NOT EXISTS aliases_source_idx ON aliases (source);
