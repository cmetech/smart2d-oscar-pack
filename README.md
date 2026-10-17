# Smart2D OSCAR pack

This private customer pack is maintained independently of OSCAR. Version 1.1.1
contains the Airflow 3 `smart2d.oracle_audit_processing_prod` DAG, its alert
template, the pack-owned `external.ext_oracle_audit_counts` table, and a small
working scaffold for each supported pack artifact family. It uses
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
3. Run `./pack-tools/build-pack.sh --output dist --expected-version 1.1.1`.
   Drag `dist/smart2d-1.1.1.tar.gz` onto Management > Packs and install it.
   The table appears in Settings > Application > External Tables as pack-owned.
   The DAG appears paused in Airflow within about five minutes.
4. Configure the source Oracle Connection `oracle_db_oscar`, then check the
   Pushgateway and Alertmanager Connections before unpausing the DAG.

Releases are built and attached to `v*` GitHub tags by
`.github/workflows/release-pack.yml`; download the archive and its `.sha256`
sidecar from the matching release.

## Pack author scaffold

The examples are namespaced to this pack and are safe to install. The greeting
job is enabled so its disabled example Hook has a valid target. The other jobs,
scheduled trigger, Hook, and HTTP probe remain disabled. The recording rule
emits a constant zero; replace it with a customer query when ready. The
configuration rule matches only the synthetic `smart2d_demo` namespace, and
the suppression is scoped to
the synthetic `smart2d_scaffold_only` component.

| Artifact | Example | What it shows |
| --- | --- | --- |
| Job definitions | `jobs/smart2d.examples.yml` | Invoke, Fabric, Python script, and Ansible runner jobs |
| Invoke task | `tasks/smart2d_demo.py` | Return a local task result |
| Fabric task | `fabfile/smart2d_demo.py` | Return a local receipt; configure an authorized target before enabling its job |
| Script | `scripts/smart2d_demo.py` | Print a message in a script worker |
| Ansible | `ansible/playbooks/smart2d_demo.yml` | Read-only local playbook using `ansible/roles`, `ansible/library`, and `ansible/collections` |
| Function catalog | `catalog/functions.yml` | Describe callable functions for the UI |
| Configuration | `conf/rules`, `conf/mappings`, `conf/roles`, `conf/dashboards` | One namespaced rule, lookup, unassigned role, and dashboard |
| Automation configuration | `conf/hooks`, `conf/suppressions`, `conf/probes` | One disabled hook, scoped maintenance window, and disabled probe |
| Scheduled trigger | `conf/triggers/smart2d.demo.yml`, `triggers/smart2d_demo.py` | Disabled function trigger with a static result |
| Recording rule | `rules/smart2d-demo.yml` | Prometheus rule group |
| Notifier template | `templates/smart2d_demo.j2`, `.yml` | Logger template and metadata |
| Airflow workflow | `workflow/dags/oracle_audit_dag.py`, `workflow/lib/ora_audit_alert.j2` | Customer DAG with pack-local support file |
| External table | `tables/ext_oracle_audit_counts.sql` | Pack-managed database table |

The `ansible/roles`, `ansible/library`, and `ansible/collections` directories
are support code for the Ansible playbook. A `celery` job can reference an
OSCAR core task, but a pack cannot define a new Celery task; use Invoke for
pack-owned Python code. Credentials and Connections remain in OSCAR's
Connections/Vault rather than in this archive.

To test the local Ansible example before release:

```bash
ANSIBLE_ROLES_PATH=ansible/roles ANSIBLE_COLLECTIONS_PATH=ansible/collections \
  ANSIBLE_LIBRARY=ansible/library ansible-playbook -i localhost, \
  ansible/playbooks/smart2d_demo.yml
```

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
