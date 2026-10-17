import os
from airflow import DAG
from airflow.sdk import dag, task, BaseHook
from airflow.providers.oracle.hooks.oracle import OracleHook
from airflow.providers.mysql.hooks.mysql import MySqlHook
from airflow.models import Connection, TaskInstance
from datetime import timedelta
import json
import logging
from prometheus_client import CollectorRegistry, Gauge, push_to_gateway
import oracledb
import MySQLdb
from typing import Dict, Any, List
import uuid
import requests  # import requests for HTTP calls
import httpx  # Using httpx instead of requests
from datetime import datetime, timezone
from jinja2 import Environment, FileSystemLoader
from pathlib import Path

# Import our custom hook
from hooks.worklog_hook import WorkLogHook, SeverityLevel, WorkLogType  # type: ignore

default_args = {
    'owner': 'airflow',
    'depends_on_past': False,
    'email_on_failure': False,
    'email_on_retry': False,
    'retries': 1,
    'retry_delay': timedelta(minutes=2)
}

# Generate a unique task ID for this run
task_id = f"WORKLOG-TEST-{uuid.uuid4().hex[:8]}"


@dag(
    dag_id='smart2d.oracle_audit_processing_prod',
    default_args=default_args,
    description='Oracle Audit Data Processing DAG',
    schedule="*/7 * * * *",
    start_date=datetime(2026, 1, 1, tzinfo=timezone.utc),
    catchup=False,
    max_active_runs=1,
    tags=['oracle', 'audit'],
)
def oracle_audit_processing():

    @task
    def create_worklog(**context) -> str:
        """Create a new worklog and add initial entries"""
        hook = WorkLogHook()

        # Create metadata for the worklog
        metadata = [
            {"key": "task_id", "value": task_id},
            {"key": "environment", "value": "production"},
            {"key": "initiated_by", "value": "airflow"}
        ]

        # Create the worklog
        worklog = hook.create_worklog(
            name="Oracle Audit Processing",
            description="Processing Oracle audit data and sending to various destinations",
            worklog_type=WorkLogType.DB,
            metadata=metadata
        )

        logging.info(f"Created worklog with ID: {worklog['id']}")

        # Add initial entry
        hook.info("Starting Oracle audit data processing workflow")

        return worklog['id']

    @task
    def fetch_oracle_data(**context) -> str:
        # Get worklog ID from previous task
        worklog_id = context['ti'].xcom_pull(task_ids='create_worklog')

        # Create hook and set the worklog ID
        hook = WorkLogHook()
        hook.set_worklog_id(worklog_id)

        hook.info("Starting to fetch Oracle audit data")

        # Get Oracle connection details using BaseHook
        oracle_connection_id = os.getenv('ORACLE_DB_OSCAR_CONNECTION_ID', 'oracle_db_oscar')
        oracle_conn = BaseHook.get_connection(oracle_connection_id)

        if not oracle_conn.host or not oracle_conn.schema or not oracle_conn.login or not oracle_conn.password:
            error_msg = "Oracle connection details are incomplete"
            hook.error(error_msg)
            raise ValueError(error_msg)

        host = oracle_conn.host
        port = oracle_conn.port or 1521

        dsn = oracledb.makedsn(host, port, service_name=oracle_conn.schema)

        def serialize_oracle_data(value):
            if isinstance(value, oracledb.LOB):
                try:
                    return value.read() or ''  # Return empty string if read() returns None
                except Exception as e:
                    error_msg = f"Failed to read LOB data: {e}"
                    logging.warning(error_msg)
                    hook.warning(error_msg)
                    return ''
            return value

        try:
            with oracledb.connect(user=oracle_conn.login, password=oracle_conn.password, dsn=dsn) as connection:
                hook.info(f"Connected to Oracle database at {host}:{port}")
                with connection.cursor() as cursor:
                    query = """
                    SELECT
                        AUDIT_TYPE,
                        SESSIONID,
                        OS_USERNAME,
                        USERHOST,
                        TERMINAL,
                        AUTHENTICATION_TYPE,
                        DBUSERNAME,
                        CLIENT_PROGRAM_NAME,
                        OBJECT_SCHEMA,
                        OBJECT_NAME,
                        SQL_TEXT,
                        SQL_BINDS,
                        EVENT_TIMESTAMP,
                        ACTION_NAME,
                        INSTANCE
                    FROM
                        UNIFIED_AUDIT_DATA
                    WHERE
                        EVENT_TIMESTAMP >= SYSDATE - 13 / (24 * 60)
                    """
                    hook.debug(f"Executing Oracle query: {query}")
                    cursor.execute(query)
                    result = cursor.fetchall()

                    columns = ['audit_type', 'sessionid', 'os_username', 'userhost', 'terminal',
                               'authentication_type', 'dbusername', 'client_program_name',
                               'object_schema', 'object_name', 'sql_text', 'sql_binds',
                               'event_timestamp', 'action_name', 'instance']

                    # Process all data while connection is still open
                    data: List[Dict[str, Any]] = []
                    for row in result:
                        row_dict = dict(zip(columns, row))
                        # Process LOB objects while connection is open
                        for key, value in row_dict.items():
                            row_dict[key] = serialize_oracle_data(value)
                        # Convert datetime to string format
                        if row_dict['event_timestamp']:
                            row_dict['event_timestamp'] = row_dict['event_timestamp'].isoformat()
                        data.append(row_dict)
        except Exception as e:
            error_msg = f"Error fetching Oracle data: {str(e)}"
            hook.error(error_msg)
            logging.error(error_msg)
            raise

        # Convert to JSON after connection is closed
        json_str = json.dumps(data)
        hook.info(f"Successfully fetched {len(data)} rows from Oracle")
        logging.info(f"Fetched {len(data)} rows from Oracle")

        # Store worklog_id in XCom for later tasks
        context['ti'].xcom_push(key='worklog_id', value=worklog_id)

        return json_str

    @task
    def write_to_prometheus(**context) -> None:
        """
        This task retrieves the Oracle audit data from XCom, loads it, and then pushes a Prometheus metric.
        The metric 'oracle_audit_count' is computed with the following columns as labels:
        userhost, terminal, authentication_type, dbusername, object_schema,
        object_name, action_name, and instance.
        """
        # Get worklog ID from XCom
        worklog_id = context['ti'].xcom_pull(task_ids='fetch_oracle_data', key='worklog_id')

        # Create hook and set the worklog ID
        hook = WorkLogHook()
        hook.set_worklog_id(worklog_id)

        hook.info("Starting to write Oracle audit data to Prometheus")

        ti = context['ti']
        data_str = ti.xcom_pull(task_ids='fetch_oracle_data')
        logging.info(f"Retrieved data from XCom: {data_str is not None}")
        if not isinstance(data_str, str):
            error_msg = "Expected string data from XCom"
            hook.error(error_msg)
            raise ValueError(error_msg)
        data_list: List[Dict[str, Any]] = json.loads(data_str)

        # Get Prometheus Pushgateway connection details using BaseHook
        pushgateway_connection_id = os.getenv('PUSHGATEWAY_CONNECTION_ID', 'pushgateway')
        prometheus_conn = BaseHook.get_connection(pushgateway_connection_id)
        pushgateway_url = f"{prometheus_conn.host}:{prometheus_conn.port}"

        hook.debug(f"Using Prometheus Pushgateway at {pushgateway_url}")

        registry = CollectorRegistry()
        # Define the gauge with the specified label columns.
        g = Gauge(
            'oracle_audit_count',
            'Oracle Audit Count',
            ['userhost', 'terminal', 'authentication_type', 'dbusername',
             'object_schema', 'object_name', 'action_name', 'instance'],
            registry=registry
        )

        for row in data_list:
            g.labels(
                userhost=str(row.get('userhost', '')),
                terminal=str(row.get('terminal', '')),
                authentication_type=str(row.get('authentication_type', '')),
                dbusername=str(row.get('dbusername', '')),
                object_schema=str(row.get('object_schema', '')),
                object_name=str(row.get('object_name', '')),
                action_name=str(row.get('action_name', '')),
                instance=str(row.get('instance', ''))
            ).inc()

        try:
            push_to_gateway(pushgateway_url, job='oracle_audit_scraper', registry=registry)
            success_msg = "Metrics pushed to Prometheus PushGateway successfully"
            hook.info(success_msg)
            logging.info(success_msg)
        except Exception as e:
            error_msg = f"Failed to push metrics to Prometheus: {str(e)}"
            hook.error(error_msg)
            logging.error(error_msg)

    @task
    def insert_to_mysql(**context) -> None:
        # Get worklog ID from XCom
        worklog_id = context['ti'].xcom_pull(task_ids='fetch_oracle_data', key='worklog_id')

        # Create hook and set the worklog ID
        hook = WorkLogHook()
        hook.set_worklog_id(worklog_id)

        hook.info("Starting to insert Oracle audit data to MySQL")

        ti = context['ti']
        data_str = ti.xcom_pull(task_ids='fetch_oracle_data')
        if not isinstance(data_str, str):
            error_msg = "Expected string data from XCom"
            hook.error(error_msg)
            raise ValueError(error_msg)
        data_list: List[Dict[str, Any]] = json.loads(data_str)

        # Get MySQL connection details using BaseHook
        mysql_conn = BaseHook.get_connection('external')
        if mysql_conn.conn_type != 'mysql' or mysql_conn.schema != 'external':
            raise ValueError('external Connection must target the external MySQL database')

        hook.debug(f"Connecting to MySQL database at {mysql_conn.host}:{mysql_conn.port or 3306}")

        connection = MySQLdb.connect(
            host=mysql_conn.host,
            user=mysql_conn.login,
            passwd=mysql_conn.password,
            db=mysql_conn.schema,
            port=mysql_conn.port or 3306,
            charset='utf8mb4'
        )

        try:
            with connection.cursor() as cursor:
                insert_query = """
                INSERT INTO ext_oracle_audit_counts (
                    id, audit_type, sessionid, os_username, userhost, terminal,
                    authentication_type, dbusername, client_program_name,
                    object_schema, object_name, sql_text, sql_binds,
                    event_timestamp, action_name, instance
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                """

                # Process the data to ensure it's in a format MySQL can handle
                rows = []
                for row in data_list:
                    try:
                        # Convert sessionid to BIGINT, handle potential conversion errors
                        sessionid = int(row.get('sessionid', '0')) if row.get('sessionid') else 0
                    except (ValueError, TypeError):
                        warning_msg = f"Invalid sessionid value: {row.get('sessionid')}. Using 0 as default."
                        hook.warning(warning_msg)
                        logging.warning(warning_msg)
                        sessionid = 0

                    processed_row = (
                        str(uuid.uuid4()),  # Generate new UUID for id
                        str(row.get('audit_type', ''))[:255],
                        sessionid,
                        str(row.get('os_username', ''))[:255],
                        str(row.get('userhost', ''))[:255],
                        str(row.get('terminal', ''))[:255],
                        str(row.get('authentication_type', ''))[:255],
                        str(row.get('dbusername', ''))[:255],
                        str(row.get('client_program_name', ''))[:255],
                        str(row.get('object_schema', ''))[:255],
                        str(row.get('object_name', ''))[:255],
                        '',  # Insert empty string for sql_text
                        '',  # Insert empty string for sql_binds
                        row.get('event_timestamp'),
                        str(row.get('action_name', ''))[:255],
                        str(row.get('instance', ''))[:255]
                    )
                    rows.append(processed_row)

                cursor.executemany(insert_query, rows)
                connection.commit()
                success_msg = f"Inserted {len(rows)} rows into ext_oracle_audit_counts"
                hook.info(success_msg)
                logging.info(success_msg)
        except MySQLdb.Error as e:
            error_msg = f"MySQL Error: {str(e)}"
            hook.error(error_msg)
            logging.error(error_msg)
            raise
        finally:
            connection.close()

    @task
    def send_alerts_to_alertmanager(**context) -> None:
        """
        This task retrieves the Oracle audit data from XCom, loads the alert template,
        and sends alerts via a POST request using httpx.
        """
        # Get worklog ID from XCom
        worklog_id = context['ti'].xcom_pull(task_ids='fetch_oracle_data', key='worklog_id')

        # Create hook and set the worklog ID
        hook = WorkLogHook()
        hook.set_worklog_id(worklog_id)

        hook.info("Starting to send Oracle audit alerts to Alertmanager")

        # Load the template bundled with this pack.
        env = Environment(
            loader=FileSystemLoader(str(Path(__file__).parent.parent / 'lib')),
            autoescape=True
        )
        template = env.get_template('ora_audit_alert.j2')

        hook.debug("Loaded alert template")

        ti = context["ti"]
        data_str = ti.xcom_pull(task_ids="fetch_oracle_data")
        if not isinstance(data_str, str):
            error_msg = "Expected string data from XCom"
            hook.error(error_msg)
            raise ValueError(error_msg)
        data_list: List[Dict[str, Any]] = json.loads(data_str)

        # Get Alertmanager connection details using BaseHook
        alertmanager_connection_id = os.getenv("ALERTMANAGER_CONNECTION_ID", "alertmanager")
        alertmgr_conn = BaseHook.get_connection(alertmanager_connection_id)
        url = f"http://{alertmgr_conn.host}:{alertmgr_conn.port}/api/v2/alerts"

        hook.debug(f"Using Alertmanager at {url}")

        alerts_payload = []
        for idx, row in enumerate(data_list):
            # Process timestamp
            if row.get("event_timestamp"):
                try:
                    dt = datetime.fromisoformat(row["event_timestamp"])
                    starts_at = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                except Exception as e:
                    warning_msg = f"Failed to parse event_timestamp ({row['event_timestamp']}): {e}"
                    hook.warning(warning_msg)
                    logging.warning(warning_msg)
                    starts_at = row["event_timestamp"]
            else:
                starts_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            # Render the bundled template with JSON-safe values.
            try:
                alert = template.render(
                    row=row,
                    starts_at=starts_at,
                    generator_url=f"http://{alertmgr_conn.host}:{alertmgr_conn.port}/smart2d.oracle_audit_processing_prod"
                )

                try:
                    alert_json = json.loads(alert)
                    alerts_payload.append(alert_json)
                except json.JSONDecodeError as je:
                    error_msg = f"JSON decode error for row {idx}: {str(je)}"
                    hook.error(error_msg)
                    logging.error(error_msg)
                    logging.error(f"Error position: line {je.lineno}, col {je.colno}")
                    raise

            except Exception as e:
                error_msg = f"Template rendering error for row {idx}: {str(e)}"
                hook.error(error_msg)
                logging.error(error_msg)
                raise

        headers = {"Content-Type": "application/json"}

        # Prepare Prometheus Pushgateway connection details
        pushgateway_connection_id = os.getenv('PUSHGATEWAY_CONNECTION_ID', 'pushgateway')
        prometheus_conn = BaseHook.get_connection(pushgateway_connection_id)
        pushgateway_url = f"{prometheus_conn.host}:{prometheus_conn.port}"

        # Prepare the metric registry and gauge used to push the success/failure metric.
        registry_status = CollectorRegistry()
        status_gauge = Gauge(
            'oracle_audit_alert_failure',
            'Indicator of alert sending success (1) or failure (0) for Oracle audit alerts',
            registry=registry_status
        )

        try:
            with httpx.Client() as client:
                hook.debug(f"Sending {len(alerts_payload)} alerts to Alertmanager")
                response = client.post(url, headers=headers, json=alerts_payload)
            if response.status_code in (200, 202):
                status_gauge.set(1)
                hook.info(f"Successfully sent {len(alerts_payload)} alerts to Alertmanager")
            else:
                status_gauge.set(0)
                error_msg = f"Failed to send alerts to Alertmanager: {response.status_code}, response: {response.text}"
                hook.error(error_msg)
            try:
                push_to_gateway(pushgateway_url, job='oracle_audit_alert_failure', registry=registry_status)
                logging.info("Pushed oracle_audit_alert_failure metric to Prometheus")
            except Exception as push_exception:
                error_msg = f"Failed to push oracle_audit_alert_failure metric to Prometheus: {push_exception}"
                hook.warning(error_msg)
                logging.error(error_msg)

            if response.status_code not in (200, 202):
                error_msg = "Alertmanager POST request failed"
                hook.error(error_msg)
                raise ValueError(error_msg)
            logging.info(f"Alerts sent to Alertmanager successfully: {len(alerts_payload)} alerts.")
        except httpx.RequestError as exc:
            error_msg = f"HTTP request error while sending alerts to Alertmanager: {exc}"
            hook.error(error_msg)
            logging.error(error_msg)
            status_gauge.set(0)
            try:
                push_to_gateway(pushgateway_url, job='oracle_audit_alert_failure', registry=registry_status)
                logging.info("Pushed oracle_audit_alert_failure metric (failure) to Prometheus")
            except Exception as push_exception:
                error_msg = f"Failed to push alert failure metric to Prometheus: {push_exception}"
                hook.warning(error_msg)
                logging.error(error_msg)
            raise ValueError("Alertmanager POST request failed due to network error") from exc

    @task
    def close_worklog(**context) -> None:
        """Close the worklog and add final entries"""
        # Get worklog ID from XCom
        worklog_id = context['ti'].xcom_pull(task_ids='fetch_oracle_data', key='worklog_id')

        # Create hook and set the worklog ID
        hook = WorkLogHook()
        hook.set_worklog_id(worklog_id)

        # Add a final entry
        hook.info("Oracle audit processing workflow completed, closing worklog")

        # Close the worklog
        closed_worklog = hook.close_worklog()

        logging.info(f"Closed worklog with ID: {closed_worklog['id']}")

    # Create the worklog first
    worklog = create_worklog()

    # Define the task dependencies
    oracle_data = fetch_oracle_data()
    prometheus_task = write_to_prometheus()
    mysql_task = insert_to_mysql()
    alert_task = send_alerts_to_alertmanager()
    worklog_close = close_worklog()

    # Update the dependencies
    worklog >> oracle_data >> [prometheus_task, mysql_task, alert_task] >> worklog_close


# Instantiate the DAG
oracle_audit_dag = oracle_audit_processing()
