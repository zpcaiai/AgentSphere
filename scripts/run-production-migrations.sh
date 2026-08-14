#!/bin/sh
set -eu

mode="${1:---apply}"
case "$mode" in
  --apply|--check) ;;
  *) echo "usage: run-production-migrations [--apply|--check]" >&2; exit 64 ;;
esac

migration_root="${AGENT_TRUST_MIGRATIONS_ROOT:-/opt/agenttrust/migrations}"
manifest="${AGENT_TRUST_MIGRATION_MANIFEST:-$migration_root/manifest.txt}"
database_url_file="${AGENT_TRUST_DATABASE_URL_FILE:-}"
database_ca_file="${AGENT_TRUST_DATABASE_CA_FILE:-}"
case "$migration_root:$manifest" in
  *[!A-Za-z0-9._/:+-]*|*..* ) echo "MIGRATION_PATH_INVALID" >&2; exit 78 ;;
esac
case "$migration_root:$manifest" in
  /*:/* ) ;;
  * ) echo "MIGRATION_PATH_INVALID" >&2; exit 78 ;;
esac
case "$database_url_file" in
  /*) ;;
  *) echo "MIGRATION_DATABASE_URL_FILE_INVALID" >&2; exit 78 ;;
esac
case "$database_ca_file" in
  /*) ;;
  *) echo "MIGRATION_DATABASE_CA_FILE_INVALID" >&2; exit 78 ;;
esac
case "$database_ca_file" in
  *..*|*[!A-Za-z0-9._/+-]* ) echo "MIGRATION_DATABASE_CA_FILE_INVALID" >&2; exit 78 ;;
esac
if [ ! -r "$database_url_file" ] || [ ! -r "$database_ca_file" ] \
  || [ -L "$database_ca_file" ] || [ ! -f "$database_ca_file" ] || [ ! -f "$manifest" ]; then
  echo "MIGRATION_INPUT_MISSING" >&2
  exit 78
fi

validate_role_name() {
  role_name=$1
  case "$role_name" in
    [a-z_]* ) ;;
    * ) return 1 ;;
  esac
  case "$role_name" in
    *[!a-z0-9_]* ) return 1 ;;
  esac
  [ "${#role_name}" -le 63 ]
}

enterprise_application_role=${AGENT_TRUST_ENTERPRISE_APPLICATION_ROLE:-}
orchestrator_application_role=${AGENT_TRUST_ORCHESTRATOR_APPLICATION_ROLE:-}
execution_application_role=${AGENT_TRUST_EXECUTION_APPLICATION_ROLE:-}
if ! validate_role_name "$enterprise_application_role" \
  || ! validate_role_name "$orchestrator_application_role" \
  || ! validate_role_name "$execution_application_role" \
  || [ "$enterprise_application_role" = "$orchestrator_application_role" ] \
  || [ "$enterprise_application_role" = "$execution_application_role" ] \
  || [ "$orchestrator_application_role" = "$execution_application_role" ]; then
  echo "MIGRATION_APPLICATION_ROLES_INVALID" >&2
  exit 78
fi

database_url=$(sed -n '1p' "$database_url_file")
if [ -n "$(sed -n '2,$p' "$database_url_file")" ]; then
  echo "MIGRATION_DATABASE_URL_FILE_INVALID" >&2
  exit 78
fi
case "$database_url" in
  postgresql://*|postgres://*) ;;
  *) echo "MIGRATION_DATABASE_URL_INVALID" >&2; exit 78 ;;
esac
case "$database_url" in
  *[[:space:]]*|*\'*|*\"*|*\\*|*\|* ) echo "MIGRATION_DATABASE_URL_INVALID" >&2; exit 78 ;;
esac
sslmode_summary=$(
  printf '%s\n' "$database_url" | awk -F '[?&]' '
    {
      count = 0
      value = ""
      for (field = 2; field <= NF; field++) {
        if ($field ~ /^sslmode=/) {
          count++
          value = substr($field, 9)
        }
      }
      print count ":" value
    }
  '
)
if [ "$sslmode_summary" != "1:verify-full" ]; then
  echo "MIGRATION_DATABASE_TLS_VERIFY_FULL_REQUIRED" >&2
  exit 78
fi
sslrootcert_summary=$(
  printf '%s\n' "$database_url" | awk -F '[?&]' '
    {
      count = 0
      value = ""
      for (field = 2; field <= NF; field++) {
        if ($field ~ /^sslrootcert=/) {
          count++
          value = substr($field, 13)
        }
      }
      print count ":" value
    }
  '
)
if [ "$sslrootcert_summary" != "1:$database_ca_file" ]; then
  echo "MIGRATION_DATABASE_TLS_ROOT_CERT_REQUIRED" >&2
  exit 78
fi

digest_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    openssl dgst -sha256 "$1" | awk '{print $NF}'
  fi
}

sql_file=$(mktemp "${TMPDIR:-/tmp}/agenttrust-migrations.XXXXXX")
trap 'rm -f "$sql_file"' EXIT HUP INT TERM
chmod 0600 "$sql_file"

cat >"$sql_file" <<'SQL'
\set ON_ERROR_STOP on
-- With pg_catalog omitted from the explicit path, PostgreSQL resolves system
-- objects there first while using public as the creation target. An explicit
-- `pg_catalog, public` path would make unqualified CREATE TABLE fail for the
-- intentionally non-superuser migration role.
SET search_path = public;
SET lock_timeout = '5s';
SET statement_timeout = '15min';
SET idle_in_transaction_session_timeout = '60s';
DO $search_path$
BEGIN
  IF current_setting('search_path') <> 'public'
     OR current_schema() <> 'public'
     OR current_schemas(true) <> ARRAY['pg_catalog', 'public']::name[] THEN
    RAISE EXCEPTION 'MIGRATION_SEARCH_PATH_INVALID';
  END IF;
END
$search_path$;
DO $posture$
DECLARE
  role_is_superuser boolean;
  role_bypasses_rls boolean;
  connection_uses_tls boolean;
BEGIN
  SELECT rolsuper, rolbypassrls
    INTO role_is_superuser, role_bypasses_rls
    FROM pg_roles WHERE rolname = current_user;
  SELECT ssl INTO connection_uses_tls
    FROM pg_stat_ssl WHERE pid = pg_backend_pid();
  IF role_is_superuser OR role_bypasses_rls OR NOT COALESCE(connection_uses_tls, false) THEN
    RAISE EXCEPTION 'MIGRATION_DATABASE_POSTURE_DENIED';
  END IF;
END
$posture$;
SELECT pg_advisory_lock(hashtextextended('agenttrust-production-migrations', 0));
SQL

cat >>"$sql_file" <<SQL
DO \$application_roles\$
DECLARE
  application_role record;
BEGIN
  IF current_user IN (
       '$enterprise_application_role', '$orchestrator_application_role',
       '$execution_application_role'
     )
     OR NOT has_schema_privilege(current_user, 'public', 'CREATE')
     OR EXISTS (
       SELECT 1
         FROM pg_namespace AS namespace,
              LATERAL aclexplode(
                COALESCE(namespace.nspacl, acldefault('n', namespace.nspowner))
              ) AS access
        WHERE namespace.nspname = 'public'
          AND access.grantee = 0
          AND access.privilege_type = 'CREATE'
     ) THEN
    RAISE EXCEPTION 'MIGRATION_SCHEMA_POSTURE_DENIED';
  END IF;
  FOR application_role IN
    SELECT role.oid, role.rolname, role.rolsuper, role.rolinherit,
           role.rolcreaterole, role.rolcreatedb, role.rolcanlogin,
           role.rolreplication, role.rolbypassrls
      FROM pg_roles AS role
     WHERE role.rolname IN (
       '$enterprise_application_role', '$orchestrator_application_role',
       '$execution_application_role'
     )
  LOOP
    IF application_role.rolsuper OR application_role.rolcreaterole
       OR application_role.rolcreatedb OR application_role.rolreplication
       OR application_role.rolbypassrls OR application_role.rolinherit
       OR NOT application_role.rolcanlogin
       OR has_schema_privilege(application_role.rolname, 'public', 'CREATE')
       OR EXISTS (SELECT 1 FROM pg_auth_members WHERE member = application_role.oid)
       OR EXISTS (
         SELECT 1
           FROM pg_class AS relation
           JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
          WHERE namespace.nspname = 'public'
            AND relation.relowner = application_role.oid
       ) THEN
      RAISE EXCEPTION 'MIGRATION_APPLICATION_ROLE_POSTURE_DENIED:%', application_role.rolname;
    END IF;
  END LOOP;
  IF (
    SELECT count(*) FROM pg_roles
     WHERE rolname IN (
       '$enterprise_application_role', '$orchestrator_application_role',
       '$execution_application_role'
     )
  ) <> 3 THEN
    RAISE EXCEPTION 'MIGRATION_APPLICATION_ROLE_MISSING';
  END IF;
END
\$application_roles\$;
SQL

if [ "$mode" = "--apply" ]; then
  cat >>"$sql_file" <<'SQL'
CREATE TABLE IF NOT EXISTS public.agenttrust_schema_migrations (
  migration_path text PRIMARY KEY,
  content_sha256 char(64) NOT NULL,
  release_id text NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT now(),
  applied_by text NOT NULL DEFAULT current_user
);
REVOKE ALL ON public.agenttrust_schema_migrations FROM PUBLIC;
SQL
else
  cat >>"$sql_file" <<'SQL'
DO $table_check$
BEGIN
  IF to_regclass('public.agenttrust_schema_migrations') IS NULL THEN
    RAISE EXCEPTION 'MIGRATION_HISTORY_MISSING';
  END IF;
END
$table_check$;
SQL
fi

release_id="${AGENT_TRUST_RELEASE_ID:-UNSPECIFIED}"
case "$release_id" in
  ''|UNSPECIFIED|WORKTREE-NO-GIT|*[!A-Za-z0-9._:-]*)
    echo "MIGRATION_RELEASE_ID_INVALID" >&2; exit 78 ;;
esac

expected_count=0
while IFS= read -r relative || [ -n "$relative" ]; do
  case "$relative" in ''|'#'*) continue ;; esac
  case "$relative" in
    *..*|/*|*[!A-Za-z0-9._/-]*) echo "MIGRATION_MANIFEST_PATH_INVALID:$relative" >&2; exit 78 ;;
  esac
  migration="$migration_root/$relative"
  if [ ! -f "$migration" ]; then
    echo "MIGRATION_FILE_MISSING:$relative" >&2
    exit 78
  fi
  digest=$(digest_file "$migration")
  expected_count=$((expected_count + 1))
  cat >>"$sql_file" <<SQL
DO \$migration_check\$
BEGIN
  IF EXISTS (
    SELECT 1 FROM public.agenttrust_schema_migrations
     WHERE migration_path = '$relative' AND content_sha256 <> '$digest'
  ) THEN
    RAISE EXCEPTION 'MIGRATION_DIGEST_MISMATCH:$relative';
  END IF;
END
\$migration_check\$;
SQL
  if [ "$mode" = "--apply" ]; then
    cat >>"$sql_file" <<SQL
SELECT EXISTS (
  SELECT 1 FROM public.agenttrust_schema_migrations
   WHERE migration_path = '$relative' AND content_sha256 = '$digest'
) AS migration_already_applied \gset
\if :migration_already_applied
\else
\i '$migration'
INSERT INTO public.agenttrust_schema_migrations(migration_path, content_sha256, release_id)
VALUES ('$relative', '$digest', '$release_id')
ON CONFLICT (migration_path) DO NOTHING;
\endif
SQL
  else
    cat >>"$sql_file" <<SQL
DO \$migration_applied\$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.agenttrust_schema_migrations
     WHERE migration_path = '$relative' AND content_sha256 = '$digest'
  ) THEN
    RAISE EXCEPTION 'MIGRATION_NOT_APPLIED:$relative';
  END IF;
END
\$migration_applied\$;
SQL
  fi
done <"$manifest"

if [ "$mode" = "--apply" ]; then
  cat >>"$sql_file" <<SQL
REVOKE CREATE ON SCHEMA public FROM $enterprise_application_role;
REVOKE CREATE ON SCHEMA public FROM $orchestrator_application_role;
REVOKE CREATE ON SCHEMA public FROM $execution_application_role;
GRANT USAGE ON SCHEMA public TO $enterprise_application_role;
GRANT USAGE ON SCHEMA public TO $orchestrator_application_role;
GRANT USAGE ON SCHEMA public TO $execution_application_role;
REVOKE ALL ON public.agenttrust_schema_migrations FROM $enterprise_application_role;
REVOKE ALL ON public.agenttrust_schema_migrations FROM $orchestrator_application_role;
REVOKE ALL ON public.agenttrust_schema_migrations FROM $execution_application_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
  public.enterprise_request_idempotency,
  public.enterprise_organizations,
  public.enterprise_tenants,
  public.enterprise_projects,
  public.enterprise_integrations,
  public.enterprise_quota_usage,
  public.enterprise_cost_usage,
  public.enterprise_api_keys,
  public.enterprise_admin_actions,
  public.enterprise_remote_actions,
  public.enterprise_approval_intents,
  public.spring_session,
  public.spring_session_attributes
TO $enterprise_application_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
  public.orchestrator_ingress_actions,
  public.orchestrator_stream_events
TO $orchestrator_application_role;
GRANT USAGE ON SEQUENCE public.orchestrator_stream_events_sequence_seq
TO $orchestrator_application_role;
REVOKE ALL ON TABLE
  public.orchestrator_ingress_actions,
  public.tool_versions,
  public.registry_snapshots,
  public.executions,
  public.idempotency_records,
  public.execution_outbox
FROM $execution_application_role;
REVOKE ALL ON SEQUENCE public.execution_fence_seq FROM $execution_application_role;
GRANT SELECT ON TABLE
  public.orchestrator_ingress_actions,
  public.tool_versions,
  public.registry_snapshots,
  public.executions
TO $execution_application_role;
GRANT INSERT, UPDATE ON TABLE public.executions TO $execution_application_role;
GRANT INSERT ON TABLE public.idempotency_records
TO $execution_application_role;
GRANT SELECT, INSERT ON TABLE public.execution_outbox TO $execution_application_role;
GRANT USAGE ON SEQUENCE public.execution_fence_seq TO $execution_application_role;
SQL
fi

cat >>"$sql_file" <<SQL
DO \$migration_count\$
BEGIN
  IF (SELECT count(*) FROM public.agenttrust_schema_migrations) <> $expected_count THEN
    RAISE EXCEPTION 'MIGRATION_HISTORY_HAS_UNEXPECTED_ENTRIES';
  END IF;
END
\$migration_count\$;
DO \$tenant_rls\$
BEGIN
  IF EXISTS (
    SELECT 1
      FROM information_schema.columns AS columns
      JOIN pg_class AS relation ON relation.relname = columns.table_name
      JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
       AND namespace.nspname = columns.table_schema
     WHERE columns.table_schema = 'public'
       AND columns.column_name = 'tenant_id'
       AND relation.relkind = 'r'
       AND (
         NOT relation.relrowsecurity
         OR NOT relation.relforcerowsecurity
         OR NOT EXISTS (
           SELECT 1 FROM pg_policies
            WHERE schemaname = columns.table_schema
              AND tablename = columns.table_name
              AND policyname = 'tenant_isolation'
              AND cmd = 'ALL'
              AND qual LIKE '%tenant_id%'
              AND qual LIKE '%app.tenant_id%'
              AND with_check LIKE '%tenant_id%'
              AND with_check LIKE '%app.tenant_id%'
         )
         OR EXISTS (
           SELECT 1 FROM pg_policies
            WHERE schemaname = columns.table_schema
              AND tablename = columns.table_name
              AND cmd IN ('ALL', 'SELECT', 'INSERT', 'UPDATE', 'DELETE')
              AND (
                permissive <> 'PERMISSIVE'
                OR roles <> ARRAY['public']::name[]
                OR policyname <> 'tenant_isolation'
                OR COALESCE(qual, '') NOT LIKE '%tenant_id%'
                OR COALESCE(qual, '') NOT LIKE '%app.tenant_id%'
                OR (
                  cmd IN ('ALL', 'INSERT', 'UPDATE')
                  AND COALESCE(with_check, '') NOT LIKE '%tenant_id%'
                )
                OR (
                  cmd IN ('ALL', 'INSERT', 'UPDATE')
                  AND COALESCE(with_check, '') NOT LIKE '%app.tenant_id%'
                )
              )
         )
       )
  ) THEN
    RAISE EXCEPTION 'MIGRATION_TENANT_RLS_INCOMPLETE';
  END IF;
END
\$tenant_rls\$;
DO \$application_grants\$
DECLARE
  table_name text;
  privilege_name text;
  enterprise_tables constant text[] := ARRAY[
    'enterprise_request_idempotency', 'enterprise_organizations', 'enterprise_tenants',
    'enterprise_projects', 'enterprise_integrations', 'enterprise_quota_usage',
    'enterprise_cost_usage', 'enterprise_api_keys', 'enterprise_admin_actions',
    'enterprise_remote_actions', 'enterprise_approval_intents', 'spring_session',
    'spring_session_attributes'
  ];
  orchestrator_tables constant text[] := ARRAY[
    'orchestrator_ingress_actions', 'orchestrator_stream_events'
  ];
  execution_tables constant text[] := ARRAY[
    'orchestrator_ingress_actions', 'tool_versions', 'registry_snapshots', 'executions',
    'idempotency_records', 'execution_outbox'
  ];
BEGIN
  FOREACH table_name IN ARRAY enterprise_tables LOOP
    IF to_regclass(format('public.%I', table_name)) IS NULL THEN
      RAISE EXCEPTION 'MIGRATION_ENTERPRISE_TABLE_MISSING:%', table_name;
    END IF;
    FOREACH privilege_name IN ARRAY ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE'] LOOP
      IF NOT has_table_privilege(
        '$enterprise_application_role', format('public.%I', table_name), privilege_name
      ) THEN
        RAISE EXCEPTION 'MIGRATION_ENTERPRISE_GRANT_MISSING:%.%', table_name, privilege_name;
      END IF;
    END LOOP;
  END LOOP;
  FOREACH table_name IN ARRAY orchestrator_tables LOOP
    IF to_regclass(format('public.%I', table_name)) IS NULL THEN
      RAISE EXCEPTION 'MIGRATION_ORCHESTRATOR_TABLE_MISSING:%', table_name;
    END IF;
    FOREACH privilege_name IN ARRAY ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE'] LOOP
      IF NOT has_table_privilege(
        '$orchestrator_application_role', format('public.%I', table_name), privilege_name
      ) THEN
        RAISE EXCEPTION 'MIGRATION_ORCHESTRATOR_GRANT_MISSING:%.%', table_name, privilege_name;
      END IF;
    END LOOP;
  END LOOP;
  IF NOT has_sequence_privilege(
    '$orchestrator_application_role',
    'public.orchestrator_stream_events_sequence_seq',
    'USAGE'
  ) THEN
    RAISE EXCEPTION 'MIGRATION_ORCHESTRATOR_SEQUENCE_GRANT_MISSING';
  END IF;
  FOREACH table_name IN ARRAY ARRAY[
    'orchestrator_ingress_actions', 'tool_versions', 'registry_snapshots', 'executions'
  ] LOOP
    IF to_regclass(format('public.%I', table_name)) IS NULL
       OR NOT has_table_privilege(
         '$execution_application_role', format('public.%I', table_name), 'SELECT'
       ) THEN
      RAISE EXCEPTION 'MIGRATION_EXECUTION_READ_GRANT_MISSING:%', table_name;
    END IF;
  END LOOP;
  IF NOT has_table_privilege(
       '$execution_application_role', 'public.executions', 'INSERT'
     )
     OR NOT has_table_privilege(
       '$execution_application_role', 'public.executions', 'UPDATE'
     )
     OR NOT has_table_privilege(
       '$execution_application_role', 'public.idempotency_records', 'INSERT'
     )
     OR NOT has_table_privilege(
       '$execution_application_role', 'public.execution_outbox', 'SELECT'
     )
     OR NOT has_table_privilege(
       '$execution_application_role', 'public.execution_outbox', 'INSERT'
     )
     OR NOT has_sequence_privilege(
       '$execution_application_role', 'public.execution_fence_seq', 'USAGE'
     ) THEN
    RAISE EXCEPTION 'MIGRATION_EXECUTION_WRITE_GRANT_MISSING';
  END IF;
  IF has_table_privilege(
       '$execution_application_role', 'public.orchestrator_ingress_actions',
       'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
     )
     OR has_table_privilege(
       '$execution_application_role', 'public.tool_versions',
       'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
     )
     OR has_table_privilege(
       '$execution_application_role', 'public.registry_snapshots',
       'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
     )
     OR has_table_privilege(
       '$execution_application_role', 'public.executions',
       'DELETE,TRUNCATE,REFERENCES,TRIGGER'
     )
     OR has_table_privilege(
       '$execution_application_role', 'public.idempotency_records',
       'SELECT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
     )
     OR has_table_privilege(
       '$execution_application_role', 'public.execution_outbox',
       'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
     ) THEN
    RAISE EXCEPTION 'MIGRATION_EXECUTION_EXCESS_TABLE_GRANT';
  END IF;
  IF has_schema_privilege('$enterprise_application_role', 'public', 'CREATE')
     OR has_schema_privilege('$orchestrator_application_role', 'public', 'CREATE')
     OR has_schema_privilege('$execution_application_role', 'public', 'CREATE')
     OR NOT has_schema_privilege('$enterprise_application_role', 'public', 'USAGE')
     OR NOT has_schema_privilege('$orchestrator_application_role', 'public', 'USAGE')
     OR NOT has_schema_privilege('$execution_application_role', 'public', 'USAGE') THEN
    RAISE EXCEPTION 'MIGRATION_APPLICATION_SCHEMA_GRANTS_INVALID';
  END IF;
  IF has_table_privilege(
       '$enterprise_application_role', 'public.agenttrust_schema_migrations',
       'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
     )
     OR has_table_privilege(
       '$orchestrator_application_role', 'public.agenttrust_schema_migrations',
       'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
     )
     OR has_table_privilege(
       '$execution_application_role', 'public.agenttrust_schema_migrations',
       'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
     ) THEN
    RAISE EXCEPTION 'MIGRATION_HISTORY_APPLICATION_ACCESS_DENIED';
  END IF;
  IF EXISTS (
    SELECT 1
      FROM pg_class AS relation
      JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = 'public'
       AND relation.relkind IN ('r', 'p')
       AND relation.relname <> ALL (enterprise_tables)
       AND has_table_privilege(
         '$enterprise_application_role', relation.oid,
         'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
       )
  ) OR EXISTS (
    SELECT 1
      FROM pg_class AS relation
      JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = 'public'
       AND relation.relkind IN ('r', 'p')
       AND relation.relname <> ALL (orchestrator_tables)
       AND has_table_privilege(
         '$orchestrator_application_role', relation.oid,
         'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
       )
  ) OR EXISTS (
    SELECT 1
      FROM pg_class AS relation
      JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = 'public'
       AND relation.relkind IN ('r', 'p')
       AND relation.relname <> ALL (execution_tables)
       AND has_table_privilege(
         '$execution_application_role', relation.oid,
         'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
       )
  ) THEN
    RAISE EXCEPTION 'MIGRATION_APPLICATION_ROLE_CROSS_DOMAIN_GRANT';
  END IF;
  IF EXISTS (
    SELECT 1
      FROM pg_class AS relation
      JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = 'public'
       AND relation.relkind IN ('r', 'p')
       AND (
         has_table_privilege(
           '$enterprise_application_role', relation.oid, 'TRUNCATE,REFERENCES,TRIGGER'
         )
         OR has_table_privilege(
           '$orchestrator_application_role', relation.oid, 'TRUNCATE,REFERENCES,TRIGGER'
         )
         OR has_table_privilege(
           '$execution_application_role', relation.oid, 'TRUNCATE,REFERENCES,TRIGGER'
         )
       )
  ) THEN
    RAISE EXCEPTION 'MIGRATION_APPLICATION_ROLE_EXCESS_TABLE_GRANT';
  END IF;
  IF EXISTS (
    SELECT 1
      FROM pg_class AS sequence
      JOIN pg_namespace AS namespace ON namespace.oid = sequence.relnamespace
     WHERE namespace.nspname = 'public'
       AND sequence.relkind = 'S'
       AND has_sequence_privilege(
         '$enterprise_application_role', sequence.oid, 'USAGE,SELECT,UPDATE'
       )
  ) OR EXISTS (
    SELECT 1
      FROM pg_class AS sequence
      JOIN pg_namespace AS namespace ON namespace.oid = sequence.relnamespace
     WHERE namespace.nspname = 'public'
       AND sequence.relkind = 'S'
       AND (
         sequence.relname <> 'orchestrator_stream_events_sequence_seq'
         OR has_sequence_privilege('$orchestrator_application_role', sequence.oid, 'SELECT,UPDATE')
       )
       AND has_sequence_privilege(
         '$orchestrator_application_role', sequence.oid, 'USAGE,SELECT,UPDATE'
       )
  ) OR EXISTS (
    SELECT 1
      FROM pg_class AS sequence
      JOIN pg_namespace AS namespace ON namespace.oid = sequence.relnamespace
     WHERE namespace.nspname = 'public'
       AND sequence.relkind = 'S'
       AND (
         sequence.relname <> 'execution_fence_seq'
         OR has_sequence_privilege('$execution_application_role', sequence.oid, 'SELECT,UPDATE')
       )
       AND has_sequence_privilege(
         '$execution_application_role', sequence.oid, 'USAGE,SELECT,UPDATE'
       )
  ) THEN
    RAISE EXCEPTION 'MIGRATION_APPLICATION_ROLE_EXCESS_SEQUENCE_GRANT';
  END IF;
END
\$application_grants\$;
SELECT pg_advisory_unlock(hashtextextended('agenttrust-production-migrations', 0));
SQL

export PGCONNECT_TIMEOUT="${AGENT_TRUST_DATABASE_CONNECT_TIMEOUT_SECONDS:-10}"
export PGAPPNAME="agenttrust-production-migrations"
# libpq accepts a connection URI through PGDATABASE. Keep credentials out of
# process arguments and out of the generated SQL file.
PGDATABASE="$database_url" psql --no-psqlrc --file "$sql_file"
