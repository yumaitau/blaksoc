-- Read access for the backup role (000_roles.sql) to every table and sequence, including the migration journal
-- so a restore knows its schema version. Runs last so tables created by the files above are covered.
GRANT USAGE ON SCHEMA public, drizzle TO blaksoc_backup;
GRANT SELECT ON ALL TABLES IN SCHEMA public, drizzle TO blaksoc_backup;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public, drizzle TO blaksoc_backup;
