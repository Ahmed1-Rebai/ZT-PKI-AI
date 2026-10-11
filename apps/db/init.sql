-- ZT-PKI-AI demo database (db VM, data zone 10.10.30.10).
-- Loaded once by the `db` Ansible role via /docker-entrypoint-initdb.d style
-- psql import. The app (web-app, 10.10.20.10) is the only allowed client
-- (gateway forward rule: 10.10.20.0/24 -> 10.10.30.10:5432).

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ztapp') THEN
    CREATE ROLE ztapp LOGIN PASSWORD 'ztapp-demo-pass';
  END IF;
END
$$;

SELECT 'CREATE DATABASE ztapp OWNER ztapp'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'ztapp')\gexec

\connect ztapp

CREATE TABLE IF NOT EXISTS access_log (
  id        bigserial PRIMARY KEY,
  ts        timestamptz NOT NULL DEFAULT now(),
  client_cn text,
  role      text,
  path      text,
  src       text
);

CREATE TABLE IF NOT EXISTS records (
  id    serial PRIMARY KEY,
  owner_cn text NOT NULL,
  label text NOT NULL,
  secret text NOT NULL
);

INSERT INTO records (owner_cn, label, secret)
SELECT v.cn, v.label, v.secret
FROM (VALUES
  ('alice@lab.local', 'payroll-q3.pdf',   'employee-only'),
  ('admin@lab.local', 'infra-keys.csv',   'admin-only'),
  ('carol@lab.local', 'contract-b.pdf',   'contractor-scope')
) AS v(cn, label, secret)
WHERE NOT EXISTS (SELECT 1 FROM records);

-- The schema is created by the postgres superuser, so grant the app role the
-- least privilege it needs: read records, append to the access log. No DROP/
-- DELETE/UPDATE. `secret` stays unreadable to the app (column-level).
GRANT CONNECT ON DATABASE ztapp TO ztapp;
GRANT USAGE ON SCHEMA public TO ztapp;
GRANT SELECT (id, owner_cn, label) ON records TO ztapp;
GRANT SELECT, INSERT ON access_log TO ztapp;
GRANT USAGE, SELECT ON SEQUENCE access_log_id_seq TO ztapp;
