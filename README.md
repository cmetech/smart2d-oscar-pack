# Smart2D OSCAR pack

This private customer pack is maintained independently of OSCAR. Version 1.0.0
contains the Airflow 3 `smart2d.oracle_audit_processing_prod` DAG, its alert
template, and the pack-owned `external.ext_oracle_audit_counts` table. It uses
the shared `external` MySQL Connection from OSCAR Connections/Vault. Credentials
are never included in the pack or its GitHub release.

## Build and install

1. Create or verify a Connection named `external` with type `mysql`, schema
   `external`, and the runtime `external` database user. The existing OSCAR
   deployment creates this database and user. The pack does not create a
   Connection because schema 7 has no secret-safe Connection artifact.
2. Check the Connection before upload:

   ```bash
   python3 .github/operator/check_connection.py --insecure --api-key-file /path/to/user-owned-api-key
   ```

   Omit `--insecure` when Middleware has a trusted TLS certificate. The key needs
   `read:workflows`. Local instances with API-key validation disabled may omit
   `--api-key-file`.
3. Run `./pack-tools/build-pack.sh --output dist --expected-version 1.0.0`.
   Drag `dist/smart2d-1.0.0.tar.gz` onto Management > Packs and install it.
   The table appears in Settings > Application > External Tables as pack-owned.
   The DAG appears paused in Airflow within about five minutes.
4. Configure the source Oracle Connection `oracle_db_oscar`, then check the
   Pushgateway and Alertmanager Connections before unpausing the DAG.

Releases are built and attached to `v*` GitHub tags by
`.github/workflows/release-pack.yml`; download the archive and its `.sha256`
sidecar from the matching release.

## Cutover from the core DAG and table

Pause `oracle_audit_processing_prod` and wait for queued and running work to
drain. Deploy the OSCAR core change that removes its source file, then run
`./oscar workflow sync`. The old DAG becomes stale; its run history remains.
Install this pack before unpausing `smart2d.oracle_audit_processing_prod`.

On an older install with `oscar.EXT_OracleAuditCounts`, back up the database,
then run [the retirement SQL](.github/operator/migrate_legacy_oracle_audit_counts.sql)
with a MySQL account allowed to read/drop the old table and write the new one.
It copies rows by ID, verifies the full rows, and only then drops the old table.
It is deliberately separate from OSCAR's `all` migrations because the pack
table must exist first. Never run it while the old DAG is still writing.

The new physical table name is lowercase because OSCAR pack table declarations
require lowercase ASCII identifiers. The pack keeps the table and its rows on
removal until an operator detaches and explicitly cleans it up.
