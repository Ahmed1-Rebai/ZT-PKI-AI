# apps/db

PostgreSQL demo database on the `db` VM (data zone `10.10.30.10:5432`).

- `init.sql` — creates the `ztapp` role/database, the `access_log` and `records`
  tables, and seeds a few rows. Applied once by the `db` Ansible role.
- Reachable only from the app zone (`10.10.20.0/24`); enforced by PostgreSQL
  `pg_hba.conf` and by the gateway forward chain (`app -> db:5432`).
