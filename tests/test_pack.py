"""Customer pack contract: installable table, isolated DAG, and no bundled credentials."""

import ast
import json
from pathlib import Path
import sys

import yaml
from jinja2 import Environment, FileSystemLoader

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pack-tools"))


def test_pack_declares_external_table_and_workflow():
    source = yaml.safe_load((ROOT / "pack.source.yml").read_text())
    assert (source["schema_version"], source["id"], source["version"]) == (7, "smart2d", "1.1.0")
    from project_pack.tables import parse_create_table

    path = ROOT / "tables/ext_oracle_audit_counts.sql"
    declaration = parse_create_table(path.read_text(), expected_name=path.stem)
    assert declaration.name == "ext_oracle_audit_counts"
    assert "INDEX idx_ext_oracle_audit_event_ts" in declaration.sql


def test_oracle_dag_uses_pack_id_and_shared_external_connection():
    path = ROOT / "workflow/dags/oracle_audit_dag.py"
    source = path.read_text()
    tree = ast.parse(source)
    ids = [keyword.value.value for node in ast.walk(tree) if isinstance(node, ast.Call)
           for keyword in node.keywords if keyword.arg == "dag_id" and isinstance(keyword.value, ast.Constant)]
    assert ids == ["smart2d.oracle_audit_processing_prod"]
    assert "BaseHook.get_connection('external')" in source
    assert "INSERT INTO ext_oracle_audit_counts" in source
    assert "oscar_db" not in source and "EXT_OracleAuditCounts" not in source


def test_release_pipeline_and_pack_have_no_secrets():
    workflow = (ROOT / ".github/workflows/release-pack.yml").read_text()
    assert 'tags:' in workflow and 'v*' in workflow
    assert 'release-pack-github.sh' in workflow
    for directory in ('workflow', 'tables', '.github/operator'):
        assert not any(path.name.endswith((".env", ".key", ".pem"))
                       for path in (ROOT / directory).rglob("*") if path.is_file())


def test_bundled_alert_template_renders_customer_values_as_json():
    template = Environment(loader=FileSystemLoader(ROOT / 'workflow/lib'), autoescape=True).get_template('ora_audit_alert.j2')
    rendered = template.render(row={'dbusername': 'O"Reilly', 'action_name': 'logon\\failed',
                                    'instance': '東京', 'object_schema': 'AUDIT', 'object_name': 'T'},
                               starts_at='2026-10-17T12:00:00Z', generator_url='http://example.test/dag')
    payload = json.loads(rendered)
    assert payload['labels']['dbusername'] == 'O"Reilly'
    assert payload['labels']['action_name'] == 'logon\\failed'
    assert payload['annotations']['object'] == 'AUDIT.T'


def test_scaffold_has_one_safe_example_for_each_installable_artifact_family():
    expected = (
        'jobs/smart2d.examples.yml', 'tasks/smart2d_demo.py',
        'fabfile/smart2d_demo.py', 'scripts/smart2d_demo.py',
        'ansible/playbooks/smart2d_demo.yml',
        'ansible/roles/smart2d_demo/tasks/main.yml',
        'ansible/library/smart2d_demo_receipt.py',
        'ansible/collections/ansible_collections/smart2d/demo/galaxy.yml',
        'ansible/collections/ansible_collections/smart2d/demo/roles/hello/tasks/main.yml',
        'rules/smart2d-demo.yml',
        'templates/smart2d_demo.j2', 'templates/smart2d_demo.yml',
        'conf/rules/smart2d-demo.json', 'conf/mappings/smart2d-demo.json',
        'conf/roles/smart2d-demo.json', 'conf/dashboards/smart2d-demo.json',
        'conf/hooks/smart2d-demo.json', 'conf/suppressions/smart2d-demo.json',
        'conf/probes/smart2d-demo.json', 'conf/triggers/smart2d.demo.yml',
        'triggers/smart2d_demo.py', 'catalog/functions.yml',
    )
    assert all((ROOT / path).is_file() for path in expected)
    jobs = yaml.safe_load((ROOT / expected[0]).read_text())
    assert {job['type'] for job in jobs} == {'invoke', 'fabric', 'script', 'ansible'}
    assert all(job['status'] == 'disabled' and 'schedule' not in job for job in jobs)
    assert yaml.safe_load((ROOT / 'conf/triggers/smart2d.demo.yml').read_text())['enabled'] is False
    for family in ('hooks', 'probes'):
        assert json.loads((ROOT / f'conf/{family}/smart2d-demo.json').read_text())[0]['enabled' if family == 'hooks' else 'status'] in (False, 'disabled')
