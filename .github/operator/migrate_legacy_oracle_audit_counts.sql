-- Run only after installing this pack, backing up both schemas, and draining the old DAG.
-- This script is intentionally outside the pack archive and OSCAR's automatic migrations.
DELIMITER //
DROP PROCEDURE IF EXISTS migrate_legacy_oracle_audit_counts//
CREATE PROCEDURE migrate_legacy_oracle_audit_counts()
BEGIN
    DECLARE missing_or_changed BIGINT DEFAULT 0;
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        RESIGNAL;
    END;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'external' AND table_name = 'ext_oracle_audit_counts'
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Install the Smart2D pack before retiring the old table';
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'oscar' AND table_name = 'EXT_OracleAuditCounts'
    ) THEN
        START TRANSACTION;
        INSERT INTO external.ext_oracle_audit_counts (
            id, audit_type, sessionid, os_username, userhost, terminal,
            authentication_type, dbusername, client_program_name, object_schema,
            object_name, sql_text, sql_binds, event_timestamp, action_name,
            instance, created_at, modified_at
        )
        SELECT id, audit_type, sessionid, os_username, userhost, terminal,
               authentication_type, dbusername, client_program_name, object_schema,
               object_name, sql_text, sql_binds, event_timestamp, action_name,
               instance, created_at, modified_at
        FROM oscar.EXT_OracleAuditCounts
        WHERE TRUE
        ON DUPLICATE KEY UPDATE id = VALUES(id);

        SELECT COUNT(*) INTO missing_or_changed
        FROM oscar.EXT_OracleAuditCounts AS old_row
        LEFT JOIN external.ext_oracle_audit_counts AS new_row ON new_row.id = old_row.id
        WHERE new_row.id IS NULL OR NOT (
            BINARY old_row.audit_type <=> BINARY new_row.audit_type AND
            old_row.sessionid <=> new_row.sessionid AND
            BINARY old_row.os_username <=> BINARY new_row.os_username AND
            BINARY old_row.userhost <=> BINARY new_row.userhost AND
            BINARY old_row.terminal <=> BINARY new_row.terminal AND
            BINARY old_row.authentication_type <=> BINARY new_row.authentication_type AND
            BINARY old_row.dbusername <=> BINARY new_row.dbusername AND
            BINARY old_row.client_program_name <=> BINARY new_row.client_program_name AND
            BINARY old_row.object_schema <=> BINARY new_row.object_schema AND
            BINARY old_row.object_name <=> BINARY new_row.object_name AND
            BINARY old_row.sql_text <=> BINARY new_row.sql_text AND
            BINARY old_row.sql_binds <=> BINARY new_row.sql_binds AND
            BINARY old_row.event_timestamp <=> BINARY new_row.event_timestamp AND
            BINARY old_row.action_name <=> BINARY new_row.action_name AND
            BINARY old_row.instance <=> BINARY new_row.instance AND
            old_row.created_at <=> new_row.created_at AND
            old_row.modified_at <=> new_row.modified_at
        );
        IF missing_or_changed > 0 THEN
            SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Row verification failed; old table retained';
        END IF;
        COMMIT;
        DROP TABLE oscar.EXT_OracleAuditCounts;
    END IF;
END//
DELIMITER ;

CALL migrate_legacy_oracle_audit_counts();
DROP PROCEDURE migrate_legacy_oracle_audit_counts;
