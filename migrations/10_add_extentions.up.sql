CREATE EXTENSION IF NOT EXISTS plpython3u WITH SCHEMA pg_catalog;
COMMENT ON EXTENSION plpython3u IS 'PL/Python3U untrusted procedural language';
CREATE EXTENSION IF NOT EXISTS pgaudit WITH SCHEMA public;
COMMENT ON EXTENSION pgaudit IS 'provides auditing functionality';
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;
COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';
CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;
COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';

