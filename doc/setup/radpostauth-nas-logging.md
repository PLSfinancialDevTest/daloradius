# FreeRADIUS Post-Auth NAS Logging for Last Connection Attempts

This guide enables daloRADIUS Last Connection Attempts to show NAS information directly from `radpostauth` records.

## Why this is needed

Some environments do not produce matching `radacct` rows for every authentication attempt. In that case, daloRADIUS cannot reliably resolve NAS shortname from accounting data and may show `(n/a)`.

Adding NAS metadata to `radpostauth` makes NAS resolution deterministic for every auth event.

## 1) Apply database migration

For existing installations, run:

```sql
ALTER TABLE radpostauth
  ADD COLUMN IF NOT EXISTS nasipaddress VARCHAR(45) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS calledstationid VARCHAR(64) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS nasidentifier VARCHAR(128) DEFAULT NULL;
```

Migration file in this repository:

- `contrib/db/migrations/2026-08-radpostauth-nas-metadata.sql`

Fresh schema includes these fields in:

- `contrib/db/fr3-mariadb-freeradius.sql`

## 2) Update FreeRADIUS SQL post-auth insert query

Edit your FreeRADIUS SQL queries file (commonly `queries.conf`) and extend the `post-auth` insert statement.

### Scripted update (recommended)

This repository includes an idempotent helper script:

- `contrib/scripts/maintenance/update-freeradius-postauth-query.sh`

Run on each FreeRADIUS node:

```bash
sudo /var/www/daloradius/contrib/scripts/maintenance/update-freeradius-postauth-query.sh
```

If your `queries.conf` lives in a custom path:

```bash
sudo /var/www/daloradius/contrib/scripts/maintenance/update-freeradius-postauth-query.sh \
  /custom/path/to/queries.conf
```

The script:

- auto-detects `queries.conf` when possible
- creates a timestamped backup (`queries.conf.bak.YYYY-MM-DD-HHMMSS`)
- updates only `postauth_query`
- preserves the existing auth timestamp token style (`%S` or `%L`)

Typical location (FreeRADIUS 3.x):

- `/etc/freeradius/3.0/mods-config/sql/main/mysql/queries.conf`

Update the `postauth_query`/post-auth INSERT to include the new columns.

Example pattern:

```sql
INSERT INTO ${postauth_table}
    (username, pass, reply, authdate, nasipaddress, calledstationid, nasidentifier)
VALUES (
    '%{SQL-User-Name}',
    '%{%{User-Password}:-%{Chap-Password}}',
    '%{reply:Packet-Type}',
    '%S',
    '%{%{NAS-IP-Address}:-}',
    '%{%{Called-Station-Id}:-}',
    '%{%{NAS-Identifier}:-}'
)
```

Notes:

- Keep your existing vendor/version query style, quoting, and escaping conventions.
- In some deployments, the query uses `%L` or DB-specific time macros instead of `%S`; keep your current timestamp pattern.
- If your file already has custom escaping helpers, use those consistently.

## 3) Reload FreeRADIUS

Run a config check and reload service.

Example commands:

```bash
freeradius -CX
systemctl reload freeradius
```

## 4) Verify logging

After a new authentication attempt, confirm values are being written:

```sql
SELECT username, reply, authdate, nasipaddress, calledstationid, nasidentifier
FROM radpostauth
ORDER BY authdate DESC
LIMIT 20;
```

If NAS columns are still empty:

- Verify AP/NAS sends the corresponding attributes.
- Check FreeRADIUS debug output (`freeradius -X`) during a test authentication.
- Confirm the SQL module in use is the one you edited.

## daloRADIUS behavior

`app/operators/rep-lastconnect.php` and CSV export now prefer native `radpostauth` NAS fields when present, then fallback to heuristic mappings for legacy rows.
