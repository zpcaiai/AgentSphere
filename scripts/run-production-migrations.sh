#!/bin/sh
set -eu

# Authentication is file-only. Clear any inherited process credential before
# invoking even validation helpers so it cannot leak to unrelated children.
unset PGPASSWORD

mode="${1:---apply}"
case "$mode" in
  --apply|--check) ;;
  *) echo "usage: run-production-migrations [--apply|--check]" >&2; exit 64 ;;
esac

migration_root="${AGENT_TRUST_MIGRATIONS_ROOT:-/opt/agenttrust/migrations}"
manifest="${AGENT_TRUST_MIGRATION_MANIFEST:-$migration_root/manifest.txt}"
database_url_file="${AGENT_TRUST_DATABASE_URL_FILE:-}"
database_password_file="${AGENT_TRUST_DATABASE_PASSWORD_FILE:-}"
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
case "$database_password_file" in
  /*) ;;
  *) echo "MIGRATION_DATABASE_PASSWORD_FILE_INVALID" >&2; exit 78 ;;
esac
case "$database_ca_file" in
  /*) ;;
  *) echo "MIGRATION_DATABASE_CA_FILE_INVALID" >&2; exit 78 ;;
esac
case "$database_ca_file" in
  *..*|*[!A-Za-z0-9._/+-]* ) echo "MIGRATION_DATABASE_CA_FILE_INVALID" >&2; exit 78 ;;
esac
if [ ! -r "$database_url_file" ] || [ ! -r "$database_ca_file" ] \
  || [ ! -r "$database_password_file" ] \
  || [ -L "$database_url_file" ] || [ -L "$database_ca_file" ] \
  || [ -L "$database_password_file" ] \
  || [ ! -f "$database_url_file" ] || [ ! -f "$database_ca_file" ] \
  || [ ! -f "$database_password_file" ] \
  || [ ! -f "$manifest" ]; then
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
enterprise_authority_application_role=${AGENT_TRUST_ENTERPRISE_AUTHORITY_APPLICATION_ROLE:-}
orchestrator_application_role=${AGENT_TRUST_ORCHESTRATOR_APPLICATION_ROLE:-}
execution_application_role=${AGENT_TRUST_EXECUTION_APPLICATION_ROLE:-}
registry_application_role=${AGENT_TRUST_REGISTRY_APPLICATION_ROLE:-}
agent_registry_application_role=${AGENT_TRUST_AGENT_REGISTRY_APPLICATION_ROLE:-}
policy_admin_application_role=${AGENT_TRUST_POLICY_ADMIN_APPLICATION_ROLE:-}
incident_release_application_role=${AGENT_TRUST_INCIDENT_RELEASE_APPLICATION_ROLE:-}
pack_marketplace_application_role=${AGENT_TRUST_PACK_MARKETPLACE_APPLICATION_ROLE:-}
approval_application_role=${AGENT_TRUST_APPROVAL_APPLICATION_ROLE:-}
pep_application_role=${AGENT_TRUST_PEP_APPLICATION_ROLE:-}
identity_application_role=${AGENT_TRUST_IDENTITY_APPLICATION_ROLE:-}
tool_proxy_application_role=${AGENT_TRUST_TOOL_PROXY_APPLICATION_ROLE:-}
evidence_application_role=${AGENT_TRUST_EVIDENCE_APPLICATION_ROLE:-}
audit_application_role=${AGENT_TRUST_AUDIT_APPLICATION_ROLE:-}
model_gateway_application_role=${AGENT_TRUST_MODEL_GATEWAY_APPLICATION_ROLE:-}
data_governance_application_role=${AGENT_TRUST_DATA_GOVERNANCE_APPLICATION_ROLE:-}
context_governance_application_role=${AGENT_TRUST_CONTEXT_GOVERNANCE_APPLICATION_ROLE:-}
runtime_anomaly_application_role=${AGENT_TRUST_RUNTIME_ANOMALY_APPLICATION_ROLE:-}
security_evaluation_application_role=${AGENT_TRUST_SECURITY_EVALUATION_APPLICATION_ROLE:-}
pack_supply_chain_application_role=${AGENT_TRUST_PACK_SUPPLY_CHAIN_APPLICATION_ROLE:-}
domain_runtime_application_role=${AGENT_TRUST_DOMAIN_RUNTIME_APPLICATION_ROLE:-}
platform_sre_application_role=${AGENT_TRUST_PLATFORM_SRE_APPLICATION_ROLE:-}
application_roles="${enterprise_application_role}
${enterprise_authority_application_role}
${orchestrator_application_role}
${execution_application_role}
${registry_application_role}
${agent_registry_application_role}
${policy_admin_application_role}
${incident_release_application_role}
${pack_marketplace_application_role}
${approval_application_role}
${pep_application_role}
${identity_application_role}
${tool_proxy_application_role}
${evidence_application_role}
${audit_application_role}
${model_gateway_application_role}
${data_governance_application_role}
${context_governance_application_role}
${runtime_anomaly_application_role}
${security_evaluation_application_role}
${pack_supply_chain_application_role}
${domain_runtime_application_role}
${platform_sre_application_role}"
for application_role_name in $application_roles; do
  if ! validate_role_name "$application_role_name"; then
    echo "MIGRATION_APPLICATION_ROLES_INVALID" >&2
    exit 78
  fi
done
if [ "$(printf '%s\n' "$application_roles" | sort -u | wc -l | tr -d ' ')" -ne 23 ]; then
  echo "MIGRATION_APPLICATION_ROLES_INVALID" >&2
  exit 78
fi

if ! database_url=$(LC_ALL=C awk '
  {
    if (NR != 1 || length($0) < 1 || length($0) > 4096 || $0 ~ /[^ -~]/) {
      invalid = 1
    }
    value = $0
  }
  END {
    if (NR != 1 || invalid) {
      exit 1
    }
    printf "%s", value
  }
' "$database_url_file"); then
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

# PGDATABASE is a database-name variable, not a portable URI transport: psql
# ignores URI structure placed there and falls back to a local socket. Parse a
# deliberately narrow passwordless URI into libpq's individual environment
# variables so neither connection metadata nor credentials enter process argv.
case "$database_url" in
  postgresql://*) database_endpoint=${database_url#postgresql://} ;;
  postgres://*) database_endpoint=${database_url#postgres://} ;;
  *) echo "MIGRATION_DATABASE_URL_INVALID" >&2; exit 78 ;;
esac
case "$database_endpoint" in
  *@*/*\?*) ;;
  *) echo "MIGRATION_DATABASE_URL_INVALID" >&2; exit 78 ;;
esac
database_authority=${database_endpoint%%/*}
database_path_query=${database_endpoint#*/}
database_user=${database_authority%%@*}
database_host_port=${database_authority#*@}
case "$database_host_port" in
  *@*) echo "MIGRATION_DATABASE_URL_INVALID" >&2; exit 78 ;;
esac
if ! validate_role_name "$database_user"; then
  echo "MIGRATION_DATABASE_USER_INVALID" >&2
  exit 78
fi
case "$database_host_port" in
  *:*)
    database_host=${database_host_port%:*}
    database_port=${database_host_port##*:}
    case "$database_host" in
      *:*) echo "MIGRATION_DATABASE_HOST_INVALID" >&2; exit 78 ;;
    esac
    ;;
  *)
    database_host=$database_host_port
    database_port=5432
    ;;
esac
case "$database_host" in
  ''|*[!A-Za-z0-9.-]*)
    echo "MIGRATION_DATABASE_HOST_INVALID" >&2; exit 78 ;;
esac
if ! printf '%s\n' "$database_host" | LC_ALL=C awk '
  length($0) > 253 { exit 1 }
  {
    label_count = split($0, labels, ".")
    for (label_number = 1; label_number <= label_count; label_number++) {
      label = labels[label_number]
      invalid_length = length(label) < 1 || length(label) > 63
      invalid_syntax = label !~ /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$/
      if (invalid_length || invalid_syntax) {
        exit 1
      }
    }
  }
'; then
  echo "MIGRATION_DATABASE_HOST_INVALID" >&2
  exit 78
fi
case "$database_port" in
  ''|*[!0-9]*) echo "MIGRATION_DATABASE_PORT_INVALID" >&2; exit 78 ;;
esac
if [ "${#database_port}" -gt 5 ] || [ "$database_port" -lt 1 ] || [ "$database_port" -gt 65535 ]; then
  echo "MIGRATION_DATABASE_PORT_INVALID" >&2
  exit 78
fi
database_name=${database_path_query%%\?*}
database_query=${database_path_query#*\?}
if ! validate_role_name "$database_name"; then
  echo "MIGRATION_DATABASE_NAME_INVALID" >&2
  exit 78
fi
case "$database_query" in
  "sslmode=verify-full&sslrootcert=$database_ca_file"|\
  "sslrootcert=$database_ca_file&sslmode=verify-full") ;;
  *) echo "MIGRATION_DATABASE_PARAMETERS_INVALID" >&2; exit 78 ;;
esac

digest_file() {
  digest_path=$1
  if command -v sha256sum >/dev/null 2>&1; then
    digest_output=$(sha256sum "$digest_path") || return 1
    digest_candidate=${digest_output%% *}
  elif command -v shasum >/dev/null 2>&1; then
    digest_output=$(shasum -a 256 "$digest_path") || return 1
    digest_candidate=${digest_output%% *}
  else
    digest_output=$(openssl dgst -sha256 "$digest_path") || return 1
    digest_candidate=${digest_output##* }
  fi
  case "$digest_candidate" in
    ''|*[!0-9a-f]*) return 1 ;;
  esac
  [ "${#digest_candidate}" -eq 64 ] || return 1
  printf '%s\n' "$digest_candidate"
}

# Migration files are authored as standalone transactions so operators can
# inspect or replay them directly.  The production runner must additionally
# bind the migration body and its immutable history row to one commit.  Strip
# only a single, outer BEGIN/COMMIT pair after lexing the entire file. Any
# transaction-control variant or backslash byte fails closed; migration SQL
# uses chr() rather than backslash escapes so psql meta-commands cannot hide in
# comments, quoted strings, or on the same line as SQL.
append_atomic_migration_body() {
  migration_path=$1
  migration_label=$2
  migration_destination=$3
  if ! awk '
    BEGIN {
      lexer_state = "normal"
    }
    function trim(value, copy) {
      copy = value
      sub(/^[ \t\r\n]+/, "", copy)
      sub(/[ \t\r\n]+$/, "", copy)
      return copy
    }
    function normalized_statement(value, copy) {
      copy = value
      gsub(/[[:space:]]+/, " ", copy)
      copy = trim(copy)
      return toupper(copy)
    }
    function is_transaction_control(value, normalized) {
      normalized = normalized_statement(value)
      return normalized ~ /^(BEGIN|START TRANSACTION|COMMIT|END|ROLLBACK|ABORT|SAVEPOINT|RELEASE SAVEPOINT|PREPARE TRANSACTION)( |$)/
    }
    {
      lines[NR] = $0
      value = trim($0)
      upper = toupper(value)
      if (index($0, "\\") != 0) {
        invalid_backslash = 1
      }
      source_line = $0
      source_length = length(source_line)
      visible_line_start = length(visible_sql) + 1
      position = 1
      while (position <= source_length) {
        character = substr(source_line, position, 1)
        pair = substr(source_line, position, 2)

        if (lexer_state == "single_quote") {
          if (character == "\047") {
            if (substr(source_line, position + 1, 1) == "\047") {
              position += 2
            } else {
              lexer_state = "normal"
              position++
            }
          } else {
            position++
          }
          continue
        }
        if (lexer_state == "double_quote") {
          if (character == "\042") {
            if (substr(source_line, position + 1, 1) == "\042") {
              position += 2
            } else {
              lexer_state = "normal"
              position++
            }
          } else {
            position++
          }
          continue
        }
        if (lexer_state == "block_comment") {
          if (pair == "/*") {
            block_depth++
            position += 2
          } else if (pair == "*/") {
            block_depth--
            position += 2
            if (block_depth == 0) {
              lexer_state = "normal"
            }
          } else {
            position++
          }
          continue
        }
        if (lexer_state == "dollar_quote") {
          remainder = substr(source_line, position)
          closing_position = index(remainder, dollar_delimiter)
          if (closing_position == 0) {
            position = source_length + 1
          } else {
            position += closing_position - 1 + length(dollar_delimiter)
            dollar_delimiter = ""
            lexer_state = "normal"
          }
          continue
        }

        if (pair == "--") {
          position = source_length + 1
        } else if (pair == "/*") {
          visible_sql = visible_sql " "
          block_depth = 1
          lexer_state = "block_comment"
          position += 2
        } else if (character == "\047") {
          visible_sql = visible_sql " "
          lexer_state = "single_quote"
          position++
        } else if (character == "\042") {
          visible_sql = visible_sql " "
          lexer_state = "double_quote"
          position++
        } else if (character == "$") {
          remainder = substr(source_line, position)
          candidate_delimiter = ""
          if (substr(remainder, 1, 2) == "$$") {
            candidate_delimiter = "$$"
          } else if (match(remainder, /^\$[A-Za-z_][A-Za-z0-9_]*\$/)) {
            candidate_delimiter = substr(remainder, RSTART, RLENGTH)
          }
          if (candidate_delimiter != "") {
            visible_sql = visible_sql " "
            dollar_delimiter = candidate_delimiter
            lexer_state = "dollar_quote"
            position += length(candidate_delimiter)
          } else {
            visible_sql = visible_sql character
            position++
          }
        } else {
          visible_sql = visible_sql character
          position++
        }
      }
      if (lexer_state == "normal") {
        visible_sql = visible_sql "\n"
      }
      visible_line = substr(visible_sql, visible_line_start)
      visible_line_upper = toupper(trim(visible_line))
      if (visible_line_upper == "BEGIN;" || visible_line_upper == "COMMIT;" || visible_line_upper == "ROLLBACK;") {
        if (upper != visible_line_upper) {
          invalid_noncanonical_transaction_line = 1
        } else {
          canonical_transaction_count++
          canonical_transaction_line[canonical_transaction_count] = NR
          canonical_transaction_kind[canonical_transaction_count] = visible_line_upper
        }
      }
    }
    END {
      if (lexer_state != "normal" || invalid_backslash || invalid_noncanonical_transaction_line) {
        exit 1
      }
      statement_count = split(visible_sql, statements, ";")
      visible_transaction_count = 0
      nonempty_statement_count = 0
      for (statement_number = 1; statement_number <= statement_count; statement_number++) {
        normalized = normalized_statement(statements[statement_number])
        if (normalized != "") {
          nonempty_statement_count++
          if (first_statement == "") {
            first_statement = normalized
          }
          last_statement = normalized
          if (is_transaction_control(normalized)) {
            visible_transaction_count++
          }
        }
      }
      if (nonempty_statement_count == 0) {
        exit 1
      }
      strip_outer_transaction = canonical_transaction_count == 2 && canonical_transaction_kind[1] == "BEGIN;" && canonical_transaction_kind[2] == "COMMIT;" && visible_transaction_count == 2 && first_statement == "BEGIN" && last_statement == "COMMIT"
      if (visible_transaction_count != 0 && !strip_outer_transaction) {
        exit 1
      }
      for (line_number = 1; line_number <= NR; line_number++) {
        if (!strip_outer_transaction || (line_number != canonical_transaction_line[1] && line_number != canonical_transaction_line[2])) {
          print lines[line_number]
        }
      }
    }
  ' "$migration_path" >>"$migration_destination"; then
    echo "MIGRATION_TRANSACTION_BOUNDARY_INVALID:$migration_label" >&2
    exit 65
  fi
}

sql_file=$(mktemp "${TMPDIR:-/tmp}/agenttrust-migrations.XXXXXX")
migration_snapshot=
password_snapshot=
pgpass_file=
psql_pid=
# Invoked indirectly through the EXIT trap.
# shellcheck disable=SC2329
cleanup_migration_files() {
  rm -f "$sql_file"
  if [ -n "$migration_snapshot" ]; then
    rm -f "$migration_snapshot"
  fi
  if [ -n "$password_snapshot" ]; then
    rm -f "$password_snapshot"
  fi
  if [ -n "$pgpass_file" ]; then
    rm -f "$pgpass_file"
  fi
}
# Invoked indirectly through the signal traps.
# shellcheck disable=SC2329
terminate_migration_runner() {
  signal_name=$1
  signal_exit_code=$2
  trap - HUP INT TERM
  if [ -n "$psql_pid" ]; then
    kill "-$signal_name" "$psql_pid" 2>/dev/null || true
    wait "$psql_pid" 2>/dev/null || true
  fi
  exit "$signal_exit_code"
}
trap cleanup_migration_files EXIT
trap 'terminate_migration_runner HUP 129' HUP
trap 'terminate_migration_runner INT 130' INT
trap 'terminate_migration_runner TERM 143' TERM
chmod 0600 "$sql_file"
password_snapshot=$(mktemp "${TMPDIR:-/tmp}/agenttrust-password-snapshot.XXXXXX")
chmod 0600 "$password_snapshot"
if ! cp "$database_password_file" "$password_snapshot"; then
  echo "MIGRATION_DATABASE_PASSWORD_SNAPSHOT_FAILED" >&2
  exit 74
fi
chmod 0400 "$password_snapshot"
pgpass_file=$(mktemp "${TMPDIR:-/tmp}/agenttrust-pgpass.XXXXXX")
chmod 0600 "$pgpass_file"
if ! escaped_database_password=$(LC_ALL=C awk '
  {
    if (NR != 1 || length($0) < 1 || length($0) > 1024 || $0 ~ /[^ -~]/) {
      invalid = 1
    }
    value = $0
  }
  END {
    if (NR != 1 || invalid) {
      exit 1
    }
    for (position = 1; position <= length(value); position++) {
      character = substr(value, position, 1)
      if (character == "\\" || character == ":") {
        printf "\\"
      }
      printf "%s", character
    }
    printf "\n"
  }
' "$password_snapshot"); then
  echo "MIGRATION_DATABASE_PASSWORD_FILE_INVALID" >&2
  exit 78
fi
printf '%s:%s:%s:%s:%s\n' \
  "$database_host" "$database_port" "$database_name" "$database_user" \
  "$escaped_database_password" >"$pgpass_file"
unset escaped_database_password
rm -f "$password_snapshot"
password_snapshot=

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
DO $transport_security$
DECLARE negotiated_tls_version text;
BEGIN
  SELECT transport.version
    INTO negotiated_tls_version
    FROM pg_catalog.pg_stat_ssl AS transport
   WHERE transport.pid = pg_backend_pid()
     AND transport.ssl;
  IF negotiated_tls_version IS DISTINCT FROM 'TLSv1.3' THEN
    RAISE EXCEPTION 'MIGRATION_TLS_VERSION_INVALID:%',
      COALESCE(negotiated_tls_version, 'NONE');
  END IF;
END
$transport_security$;
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
       '$enterprise_application_role', '$enterprise_authority_application_role',
       '$orchestrator_application_role',
       '$execution_application_role', '$registry_application_role', '$approval_application_role',
       '$agent_registry_application_role',
       '$policy_admin_application_role',
       '$incident_release_application_role', '$pack_marketplace_application_role',
       '$pep_application_role', '$identity_application_role', '$tool_proxy_application_role',
       '$evidence_application_role', '$audit_application_role',
       '$model_gateway_application_role', '$data_governance_application_role',
       '$context_governance_application_role', '$runtime_anomaly_application_role',
       '$security_evaluation_application_role', '$pack_supply_chain_application_role',
       '$domain_runtime_application_role', '$platform_sre_application_role'
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
       '$enterprise_application_role', '$enterprise_authority_application_role',
       '$orchestrator_application_role',
       '$execution_application_role', '$registry_application_role', '$approval_application_role',
       '$agent_registry_application_role',
       '$policy_admin_application_role',
       '$incident_release_application_role', '$pack_marketplace_application_role',
       '$pep_application_role', '$identity_application_role', '$tool_proxy_application_role',
       '$evidence_application_role', '$audit_application_role',
       '$model_gateway_application_role', '$data_governance_application_role',
       '$context_governance_application_role', '$runtime_anomaly_application_role',
       '$security_evaluation_application_role', '$pack_supply_chain_application_role',
       '$domain_runtime_application_role', '$platform_sre_application_role'
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
       '$enterprise_application_role', '$enterprise_authority_application_role',
       '$orchestrator_application_role',
       '$execution_application_role', '$registry_application_role', '$approval_application_role',
       '$agent_registry_application_role',
       '$policy_admin_application_role',
       '$incident_release_application_role', '$pack_marketplace_application_role',
       '$pep_application_role', '$identity_application_role', '$tool_proxy_application_role',
       '$evidence_application_role', '$audit_application_role',
       '$model_gateway_application_role', '$data_governance_application_role',
       '$context_governance_application_role', '$runtime_anomaly_application_role',
       '$security_evaluation_application_role', '$pack_supply_chain_application_role',
       '$domain_runtime_application_role', '$platform_sre_application_role'
     )
  ) <> 23 THEN
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
  migration_snapshot=$(mktemp "${TMPDIR:-/tmp}/agenttrust-migration-snapshot.XXXXXX")
  chmod 0600 "$migration_snapshot"
  if ! cp "$migration" "$migration_snapshot"; then
    echo "MIGRATION_SNAPSHOT_FAILED:$relative" >&2
    exit 74
  fi
  chmod 0400 "$migration_snapshot"
  if ! digest=$(digest_file "$migration_snapshot"); then
    echo "MIGRATION_DIGEST_INVALID:$relative" >&2
    exit 65
  fi
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
BEGIN;
SQL
    append_atomic_migration_body "$migration_snapshot" "$relative" "$sql_file"
    cat >>"$sql_file" <<SQL
INSERT INTO public.agenttrust_schema_migrations(migration_path, content_sha256, release_id)
VALUES ('$relative', '$digest', '$release_id');
COMMIT;
\endif
SQL
  else
    append_atomic_migration_body "$migration_snapshot" "$relative" /dev/null
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
  rm -f "$migration_snapshot"
  migration_snapshot=
done <"$manifest"

if [ "$mode" = "--apply" ]; then
  cat >>"$sql_file" <<SQL
BEGIN;
DO \$database_acl\$
DECLARE
  role_name text;
BEGIN
  EXECUTE format(
    'REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC',
    current_database()
  );
  FOREACH role_name IN ARRAY ARRAY[
    '$enterprise_application_role', '$enterprise_authority_application_role',
    '$orchestrator_application_role', '$execution_application_role',
    '$registry_application_role', '$agent_registry_application_role',
    '$policy_admin_application_role',
    '$incident_release_application_role', '$pack_marketplace_application_role',
    '$approval_application_role', '$pep_application_role',
    '$identity_application_role', '$tool_proxy_application_role',
    '$evidence_application_role', '$audit_application_role',
    '$model_gateway_application_role', '$data_governance_application_role',
    '$context_governance_application_role', '$runtime_anomaly_application_role',
    '$security_evaluation_application_role', '$pack_supply_chain_application_role',
    '$domain_runtime_application_role', '$platform_sre_application_role'
  ] LOOP
    EXECUTE format(
      'GRANT CONNECT ON DATABASE %I TO %I', current_database(), role_name
    );
    EXECUTE format(
      'REVOKE TEMPORARY ON DATABASE %I FROM %I', current_database(), role_name
    );
  END LOOP;
END
\$database_acl\$;
REVOKE CREATE ON SCHEMA public FROM $enterprise_application_role;
REVOKE CREATE ON SCHEMA public FROM $enterprise_authority_application_role;
REVOKE CREATE ON SCHEMA public FROM $orchestrator_application_role;
REVOKE CREATE ON SCHEMA public FROM $execution_application_role;
REVOKE CREATE ON SCHEMA public FROM $registry_application_role;
REVOKE CREATE ON SCHEMA public FROM $agent_registry_application_role;
REVOKE CREATE ON SCHEMA public FROM $policy_admin_application_role;
REVOKE CREATE ON SCHEMA public FROM $incident_release_application_role;
REVOKE CREATE ON SCHEMA public FROM $pack_marketplace_application_role;
REVOKE CREATE ON SCHEMA public FROM $approval_application_role;
REVOKE CREATE ON SCHEMA public FROM $pep_application_role;
REVOKE CREATE ON SCHEMA public FROM $identity_application_role;
REVOKE CREATE ON SCHEMA public FROM $tool_proxy_application_role;
REVOKE CREATE ON SCHEMA public FROM $evidence_application_role;
REVOKE CREATE ON SCHEMA public FROM $audit_application_role;
GRANT USAGE ON SCHEMA public TO $enterprise_application_role;
GRANT USAGE ON SCHEMA public TO $enterprise_authority_application_role;
GRANT USAGE ON SCHEMA public TO $orchestrator_application_role;
GRANT USAGE ON SCHEMA public TO $execution_application_role;
GRANT USAGE ON SCHEMA public TO $registry_application_role;
GRANT USAGE ON SCHEMA public TO $agent_registry_application_role;
GRANT USAGE ON SCHEMA public TO $policy_admin_application_role;
GRANT USAGE ON SCHEMA public TO $incident_release_application_role;
GRANT USAGE ON SCHEMA public TO $pack_marketplace_application_role;
GRANT USAGE ON SCHEMA public TO $approval_application_role;
GRANT USAGE ON SCHEMA public TO $pep_application_role;
GRANT USAGE ON SCHEMA public TO $identity_application_role;
GRANT USAGE ON SCHEMA public TO $tool_proxy_application_role;
GRANT USAGE ON SCHEMA public TO $evidence_application_role;
GRANT USAGE ON SCHEMA public TO $audit_application_role;
REVOKE ALL ON public.agenttrust_schema_migrations FROM $enterprise_application_role;
REVOKE ALL ON public.agenttrust_schema_migrations FROM $enterprise_authority_application_role;
REVOKE ALL ON public.agenttrust_schema_migrations FROM $orchestrator_application_role;
REVOKE ALL ON public.agenttrust_schema_migrations FROM $execution_application_role;
REVOKE ALL ON public.agenttrust_schema_migrations FROM $registry_application_role;
REVOKE ALL ON public.agenttrust_schema_migrations FROM $agent_registry_application_role;
REVOKE ALL ON public.agenttrust_schema_migrations FROM $policy_admin_application_role;
REVOKE ALL ON public.agenttrust_schema_migrations FROM $incident_release_application_role;
REVOKE ALL ON public.agenttrust_schema_migrations FROM $pack_marketplace_application_role;
REVOKE ALL ON public.agenttrust_schema_migrations FROM $approval_application_role;
REVOKE ALL ON public.agenttrust_schema_migrations FROM $pep_application_role;
REVOKE ALL ON public.agenttrust_schema_migrations FROM $identity_application_role;
REVOKE ALL ON public.agenttrust_schema_migrations FROM $tool_proxy_application_role;
REVOKE ALL ON public.agenttrust_schema_migrations FROM $evidence_application_role;
REVOKE ALL ON public.agenttrust_schema_migrations FROM $audit_application_role;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM $enterprise_application_role;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM $enterprise_authority_application_role;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM $orchestrator_application_role;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM $execution_application_role;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM $registry_application_role;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM $agent_registry_application_role;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM $policy_admin_application_role;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM $incident_release_application_role;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM $pack_marketplace_application_role;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM $approval_application_role;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM $pep_application_role;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM $identity_application_role;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM $tool_proxy_application_role;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM $evidence_application_role;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM $audit_application_role;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM $enterprise_application_role;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM $enterprise_authority_application_role;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM $orchestrator_application_role;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM $execution_application_role;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM $registry_application_role;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM $agent_registry_application_role;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM $policy_admin_application_role;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM $incident_release_application_role;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM $pack_marketplace_application_role;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM $approval_application_role;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM $pep_application_role;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM $identity_application_role;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM $tool_proxy_application_role;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM $evidence_application_role;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM $audit_application_role;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM $enterprise_application_role;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM $enterprise_authority_application_role;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM $orchestrator_application_role;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM $execution_application_role;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM $registry_application_role;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM $agent_registry_application_role;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM $policy_admin_application_role;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM $incident_release_application_role;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM $pack_marketplace_application_role;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM $approval_application_role;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM $pep_application_role;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM $identity_application_role;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM $tool_proxy_application_role;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM $evidence_application_role;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM $audit_application_role;
DO \$column_acl\$
DECLARE
  column_acl record;
BEGIN
  FOR column_acl IN
    SELECT grants.table_schema, grants.table_name, grants.column_name,
           grants.grantee, grants.privilege_type
      FROM information_schema.column_privileges AS grants
     WHERE grants.table_schema = 'public'
       AND grants.grantee IN (
         '$enterprise_application_role', '$enterprise_authority_application_role',
         '$orchestrator_application_role', '$execution_application_role',
         '$registry_application_role', '$agent_registry_application_role',
         '$policy_admin_application_role',
         '$incident_release_application_role', '$pack_marketplace_application_role',
         '$approval_application_role', '$pep_application_role',
         '$identity_application_role', '$tool_proxy_application_role',
         '$evidence_application_role', '$audit_application_role'
       )
  LOOP
    EXECUTE format(
      'REVOKE %s (%I) ON TABLE %I.%I FROM %I',
      column_acl.privilege_type, column_acl.column_name,
      column_acl.table_schema, column_acl.table_name, column_acl.grantee
    );
  END LOOP;
END
\$column_acl\$;
GRANT SELECT, INSERT ON TABLE public.enterprise_remote_actions,
  public.enterprise_approval_intents TO $enterprise_application_role;
GRANT UPDATE (status, response_payload, evidence_ref, attempts, next_attempt_at,
              last_error_code, updated_at)
ON TABLE public.enterprise_remote_actions TO $enterprise_application_role;
GRANT UPDATE (status, response_payload, evidence_ref, attempts, next_attempt_at,
              last_error_code, updated_at)
ON TABLE public.enterprise_approval_intents TO $enterprise_application_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.spring_session,
  public.spring_session_attributes TO $enterprise_application_role;
GRANT SELECT, INSERT ON TABLE
  public.enterprise_principal_assertion_replay,
  public.enterprise_action_ingress,
  public.enterprise_resource_versions,
  public.enterprise_authority_executions
TO $enterprise_authority_application_role;
GRANT INSERT ON TABLE public.enterprise_authority_outbox
TO $enterprise_authority_application_role;
GRANT UPDATE (state, receipt, updated_at) ON TABLE public.enterprise_action_ingress
TO $enterprise_authority_application_role;
GRANT UPDATE (resource_version, action_hash, ledger_execution_id, fence_digest, updated_at)
ON TABLE public.enterprise_resource_versions TO $enterprise_authority_application_role;
GRANT UPDATE (state, safe_result, safe_result_digest, stable_error, updated_at)
ON TABLE public.enterprise_authority_executions TO $enterprise_authority_application_role;
GRANT SELECT, INSERT ON TABLE
  public.enterprise_tenants,
  public.enterprise_organizations,
  public.enterprise_projects,
  public.enterprise_integrations,
  public.enterprise_quota_usage,
  public.enterprise_cost_usage,
  public.enterprise_api_keys,
  public.enterprise_admin_actions
TO $enterprise_authority_application_role;
GRANT UPDATE (used, limit_value) ON TABLE public.enterprise_quota_usage
TO $enterprise_authority_application_role;
GRANT UPDATE (revoked_at, revocation_reason) ON TABLE public.enterprise_api_keys
TO $enterprise_authority_application_role;
GRANT SELECT, INSERT ON TABLE
  public.orchestrator_ingress_actions,
  public.orchestrator_stream_events
TO $orchestrator_application_role;
GRANT UPDATE (status, updated_at) ON TABLE public.orchestrator_ingress_actions
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
REVOKE ALL ON TABLE
  public.tools,
  public.tool_versions,
  public.tool_signatures,
  public.registry_events,
  public.registry_snapshots,
  public.registry_publisher_keys,
  public.registry_tenant_revisions,
  public.registry_idempotency_records,
  public.executor_profiles,
  public.credential_profiles,
  public.approval_profiles,
  public.capabilities,
  public.capability_versions
FROM $registry_application_role;
GRANT SELECT ON TABLE
  public.tools,
  public.tool_versions,
  public.tool_signatures,
  public.registry_events,
  public.registry_snapshots,
  public.registry_publisher_keys,
  public.registry_tenant_revisions,
  public.registry_idempotency_records,
  public.executor_profiles,
  public.credential_profiles,
  public.approval_profiles,
  public.capabilities,
  public.capability_versions
TO $registry_application_role;
GRANT INSERT ON TABLE
  public.tools,
  public.tool_versions,
  public.tool_signatures,
  public.registry_events,
  public.registry_snapshots,
  public.registry_publisher_keys,
  public.registry_tenant_revisions,
  public.registry_idempotency_records
TO $registry_application_role;
GRANT UPDATE ON TABLE
  public.tool_versions,
  public.registry_publisher_keys,
  public.registry_tenant_revisions
TO $registry_application_role;
GRANT SELECT, INSERT ON TABLE
  public.agent_assets,
  public.agent_discovery_facts,
  public.agent_posture_findings,
  public.agent_boms,
  public.agent_ownership_confirmations,
  public.agent_relationship_edges,
  public.agent_relationship_supersessions,
  public.agent_posture_resolutions,
  public.agent_lifecycle_records,
  public.agent_registry_idempotency,
  public.agent_registry_audit_heads,
  public.agent_registry_audit_events,
  public.agent_registry_outbox
TO $agent_registry_application_role;
GRANT UPDATE ON TABLE public.agent_assets, public.agent_registry_audit_heads
TO $agent_registry_application_role;
REVOKE ALL ON TABLE
  public.policy_sources,
  public.policy_analysis_results,
  public.policy_simulation_runs,
  public.policy_impact_reports,
  public.policy_reviews,
  public.policy_bundles,
  public.policy_exceptions,
  public.policy_promotions,
  public.policy_activation_intents,
  public.policy_resource_versions,
  public.policy_principal_assertion_replay,
  public.policy_action_ingress,
  public.policy_authority_executions,
  public.policy_evidence_events,
  public.policy_evidence_outbox
FROM $policy_admin_application_role;
GRANT SELECT, INSERT ON TABLE
  public.policy_sources,
  public.policy_analysis_results,
  public.policy_simulation_runs,
  public.policy_impact_reports,
  public.policy_reviews,
  public.policy_bundles,
  public.policy_exceptions,
  public.policy_promotions,
  public.policy_activation_intents,
  public.policy_resource_versions,
  public.policy_principal_assertion_replay,
  public.policy_action_ingress,
  public.policy_authority_executions,
  public.policy_evidence_events
TO $policy_admin_application_role;
GRANT INSERT ON TABLE public.policy_evidence_outbox
TO $policy_admin_application_role;
GRANT UPDATE (lifecycle_state, updated_at) ON TABLE public.policy_sources
TO $policy_admin_application_role;
GRANT UPDATE (status, deprecated_at) ON TABLE public.policy_bundles
TO $policy_admin_application_role;
GRANT UPDATE (revoked_at, revocation_reason_digest, expired_at)
ON TABLE public.policy_exceptions TO $policy_admin_application_role;
GRANT UPDATE (state, completed_at) ON TABLE public.policy_promotions
TO $policy_admin_application_role;
GRANT UPDATE (state, claim_owner, claim_expires_at, acknowledgement_digest,
              acknowledgement, updated_at, activated_at)
ON TABLE public.policy_activation_intents TO $policy_admin_application_role;
GRANT UPDATE (resource_version, action_hash, ledger_execution_id, fence_digest, updated_at)
ON TABLE public.policy_resource_versions TO $policy_admin_application_role;
GRANT UPDATE (state, receipt, updated_at) ON TABLE public.policy_action_ingress
TO $policy_admin_application_role;
GRANT UPDATE (state, safe_result, safe_result_digest, stable_error, updated_at)
ON TABLE public.policy_authority_executions TO $policy_admin_application_role;
REVOKE ALL ON TABLE
  public.incidents,
  public.replay_runs,
  public.release_gate_results,
  public.incident_principal_assertion_replay,
  public.incident_action_ingress,
  public.incident_resource_versions,
  public.incident_authority_executions,
  public.incident_timeline,
  public.containment_actions,
  public.incident_evidence_preservations,
  public.replay_plans,
  public.root_cause_reports,
  public.incident_recertifications,
  public.release_gate_runs,
  public.release_gate_certificates,
  public.release_canary_events,
  public.incident_evidence_events,
  public.incident_evidence_outbox
FROM $incident_release_application_role;
GRANT SELECT, INSERT ON TABLE
  public.incidents,
  public.replay_runs,
  public.incident_principal_assertion_replay,
  public.incident_action_ingress,
  public.incident_resource_versions,
  public.incident_authority_executions,
  public.incident_timeline,
  public.containment_actions,
  public.incident_evidence_preservations,
  public.replay_plans,
  public.root_cause_reports,
  public.incident_recertifications,
  public.release_gate_runs,
  public.release_gate_certificates,
  public.release_canary_events
TO $incident_release_application_role;
GRANT INSERT ON TABLE public.incident_evidence_events,
  public.incident_evidence_outbox TO $incident_release_application_role;
GRANT UPDATE (status, owner, severity, resource_version, updated_at)
ON TABLE public.incidents TO $incident_release_application_role;
GRANT UPDATE (state, receipt, updated_at)
ON TABLE public.incident_action_ingress TO $incident_release_application_role;
GRANT UPDATE (resource_version, action_hash, ledger_execution_id, fence_digest, updated_at)
ON TABLE public.incident_resource_versions TO $incident_release_application_role;
GRANT UPDATE (state, execution_owner, execution_lease_until, safe_result,
              safe_result_digest, stable_error, updated_at)
ON TABLE public.incident_authority_executions TO $incident_release_application_role;
GRANT UPDATE (state, updated_at)
ON TABLE public.release_gate_runs TO $incident_release_application_role;
REVOKE ALL ON TABLE
  public.marketplace_publishers,
  public.marketplace_publisher_keys,
  public.marketplace_pack_names,
  public.marketplace_tenant_catalog,
  public.marketplace_releases,
  public.marketplace_installations,
  public.marketplace_upgrade_plans,
  public.marketplace_canary_results,
  public.marketplace_revocations,
  public.marketplace_resource_versions,
  public.marketplace_principal_assertion_replay,
  public.marketplace_action_ingress,
  public.marketplace_authority_executions,
  public.marketplace_evidence_events,
  public.marketplace_evidence_outbox
FROM $pack_marketplace_application_role;
GRANT SELECT, INSERT ON TABLE
  public.marketplace_publishers,
  public.marketplace_publisher_keys,
  public.marketplace_pack_names,
  public.marketplace_tenant_catalog,
  public.marketplace_releases,
  public.marketplace_installations,
  public.marketplace_upgrade_plans,
  public.marketplace_canary_results,
  public.marketplace_revocations,
  public.marketplace_resource_versions,
  public.marketplace_principal_assertion_replay,
  public.marketplace_action_ingress,
  public.marketplace_authority_executions
TO $pack_marketplace_application_role;
GRANT INSERT ON TABLE public.marketplace_evidence_events,
  public.marketplace_evidence_outbox TO $pack_marketplace_application_role;
GRANT UPDATE (trust_status, verified_by, verified_at, revoked_at, updated_at)
ON TABLE public.marketplace_publishers TO $pack_marketplace_application_role;
GRANT UPDATE (status, revoked_at)
ON TABLE public.marketplace_publisher_keys TO $pack_marketplace_application_role;
GRANT UPDATE (control_plane_version, region, entitlements, allowed_compatibility,
              minimum_publisher_trust, maximum_risk, configured_by, updated_at)
ON TABLE public.marketplace_tenant_catalog TO $pack_marketplace_application_role;
GRANT UPDATE (review_status, reviewed_by, review_digest, published_at, revoked_at, updated_at)
ON TABLE public.marketplace_releases TO $pack_marketplace_application_role;
GRANT UPDATE (state, approved_by, approval_digest, artifact_receipt_digest,
              previous_installation_id, production_certificate_digest,
              deactivation_reason_digest, approved_at, installed_at, activated_at,
              deactivated_at, revoked_at, updated_at)
ON TABLE public.marketplace_installations TO $pack_marketplace_application_role;
GRANT UPDATE (state, rollback_reason_digest, completed_at, rolled_back_at, updated_at)
ON TABLE public.marketplace_upgrade_plans TO $pack_marketplace_application_role;
GRANT UPDATE (resource_version, action_hash, policy_decision_id, ledger_entry_id,
              ledger_execution_id, fence_digest, updated_at)
ON TABLE public.marketplace_resource_versions TO $pack_marketplace_application_role;
GRANT UPDATE (state, receipt, updated_at)
ON TABLE public.marketplace_action_ingress TO $pack_marketplace_application_role;
GRANT UPDATE (state, safe_result, safe_result_digest, stable_error, updated_at)
ON TABLE public.marketplace_authority_executions TO $pack_marketplace_application_role;
REVOKE ALL ON TABLE
  public.pep_authorization_requests,
  public.pep_policy_decisions,
  public.pep_execution_authorizations,
  public.pep_human_assertion_uses,
  public.pep_governance_evidence,
  public.pep_evidence_outbox,
  public.pep_policy_bundle_artifacts,
  public.pep_policy_activation_requests,
  public.pep_active_policy_bundles,
  public.pep_policy_activation_evidence,
  public.pep_policy_activation_outbox
FROM $pep_application_role;
GRANT SELECT, INSERT ON TABLE
  public.pep_authorization_requests,
  public.pep_policy_decisions,
  public.pep_execution_authorizations,
  public.pep_human_assertion_uses,
  public.pep_governance_evidence,
  public.pep_evidence_outbox,
  public.pep_policy_bundle_artifacts,
  public.pep_policy_activation_requests,
  public.pep_active_policy_bundles,
  public.pep_policy_activation_evidence,
  public.pep_policy_activation_outbox
TO $pep_application_role;
GRANT UPDATE ON TABLE public.pep_authorization_requests TO $pep_application_role;
GRANT UPDATE (state, claim_owner, claim_expires_at, pdp_ack_digest, pdp_ack_body,
              response_digest, response_body, completed_at, updated_at)
ON TABLE public.pep_policy_activation_requests TO $pep_application_role;
GRANT UPDATE (activation_id, policy_id, sequence, bundle_digest, policy_version,
              pdp_ack_digest, activated_at)
ON TABLE public.pep_active_policy_bundles TO $pep_application_role;
REVOKE ALL ON TABLE
  public.approval_cases,
  public.approval_decisions,
  public.approval_grants,
  public.approval_notification_outbox,
  public.approval_consumptions,
  public.approval_mutation_receipts,
  public.approval_principal_assertion_uses,
  public.approval_events,
  public.approval_decision_evidence_receipts,
  public.approval_decision_evidence_outbox
FROM $approval_application_role;
GRANT SELECT, INSERT ON TABLE
  public.approval_cases,
  public.approval_decisions,
  public.approval_grants,
  public.approval_notification_outbox,
  public.approval_consumptions,
  public.approval_mutation_receipts,
  public.approval_principal_assertion_uses,
  public.approval_events,
  public.approval_decision_evidence_receipts,
  public.approval_decision_evidence_outbox
TO $approval_application_role;
GRANT UPDATE (status, updated_at) ON TABLE public.approval_cases
TO $approval_application_role;
GRANT UPDATE (remaining_uses, revoked_at, revoked_by, revocation_reason_digest,
              revocation_receipt, last_consumed_at)
ON TABLE public.approval_grants TO $approval_application_role;
GRANT UPDATE (delivery_attempts, next_attempt_at, lease_owner, lease_expires_at,
              last_attempt_at, last_error_code, signed_authority_receipt, delivered_at)
ON TABLE public.approval_decision_evidence_outbox TO $approval_application_role;
REVOKE ALL ON TABLE
  public.agent_principals,
  public.credential_profiles,
  public.credential_handles,
  public.identity_revocations,
  public.identity_tenant_epochs,
  public.identity_task_lifecycle,
  public.identity_credential_signing_keys,
  public.identity_credential_idempotency,
  public.identity_credential_events,
  public.identity_credential_outbox
FROM $identity_application_role;
GRANT SELECT ON TABLE public.agent_principals, public.credential_profiles,
  public.identity_credential_signing_keys TO $identity_application_role;
GRANT SELECT, INSERT, UPDATE ON TABLE public.credential_handles,
  public.identity_tenant_epochs, public.identity_task_lifecycle
TO $identity_application_role;
GRANT SELECT, INSERT ON TABLE public.identity_revocations,
  public.identity_credential_idempotency TO $identity_application_role;
GRANT INSERT ON TABLE public.identity_credential_events,
  public.identity_credential_outbox TO $identity_application_role;
REVOKE ALL ON TABLE public.tool_proxy_invocations,
  public.tool_proxy_audit_events, public.tool_proxy_outbox
FROM $tool_proxy_application_role;
GRANT SELECT, INSERT, UPDATE ON TABLE public.tool_proxy_invocations
TO $tool_proxy_application_role;
GRANT INSERT ON TABLE public.tool_proxy_audit_events, public.tool_proxy_outbox
TO $tool_proxy_application_role;
REVOKE ALL ON TABLE
  public.audit_events, public.evidence_chain_heads,
  public.execution_evidence_receipts, public.evidence_artifacts,
  public.evidence_artifact_requests, public.evidence_event_requests,
  public.authority_evidence_event_requests,
  public.evidence_packages,
  public.evidence_package_requests, public.evaluation_results,
  public.evidence_outbox, public.executions, public.pep_execution_authorizations,
  public.orchestrator_tasks, public.orchestrator_ingress_actions
FROM $evidence_application_role;
GRANT SELECT, INSERT ON TABLE
  public.audit_events, public.execution_evidence_receipts,
  public.evidence_artifacts, public.evidence_artifact_requests,
  public.evidence_event_requests, public.authority_evidence_event_requests,
  public.evidence_packages,
  public.evidence_package_requests,
  public.evaluation_results, public.evidence_outbox
TO $evidence_application_role;
GRANT SELECT, INSERT, UPDATE ON TABLE public.evidence_chain_heads
TO $evidence_application_role;
GRANT SELECT ON TABLE public.executions, public.pep_execution_authorizations,
  public.orchestrator_tasks, public.orchestrator_ingress_actions
TO $evidence_application_role;
REVOKE ALL ON TABLE
  public.audit_records, public.audit_chain_heads, public.audit_retention_policies,
  public.legal_holds, public.audit_export_manifests, public.audit_deletion_proofs,
  public.audit_operation_replays, public.audit_retention_outbox,
  public.audit_human_assertion_uses, public.audit_control_definitions, public.audit_evidence_nodes,
  public.audit_evidence_edges
FROM $audit_application_role;
GRANT SELECT, INSERT ON TABLE
  public.audit_records, public.audit_retention_policies, public.legal_holds,
  public.audit_export_manifests, public.audit_deletion_proofs,
  public.audit_operation_replays, public.audit_retention_outbox,
  public.audit_human_assertion_uses, public.audit_control_definitions, public.audit_evidence_nodes,
  public.audit_evidence_edges
TO $audit_application_role;
GRANT SELECT, INSERT, UPDATE ON TABLE public.audit_chain_heads
TO $audit_application_role;
GRANT UPDATE (released_by, released_at, release_reason) ON TABLE public.legal_holds
TO $audit_application_role;
DO \$production_authority_role_baseline\$
DECLARE role_name text;
BEGIN
  FOREACH role_name IN ARRAY ARRAY[
    '$model_gateway_application_role', '$data_governance_application_role',
    '$context_governance_application_role', '$runtime_anomaly_application_role',
    '$security_evaluation_application_role', '$pack_supply_chain_application_role',
    '$domain_runtime_application_role', '$platform_sre_application_role'
  ] LOOP
    EXECUTE format('REVOKE CREATE ON SCHEMA public FROM %I', role_name);
    EXECUTE format('GRANT USAGE ON SCHEMA public TO %I', role_name);
    EXECUTE format('REVOKE ALL ON public.agenttrust_schema_migrations FROM %I', role_name);
    EXECUTE format('REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM %I', role_name);
    EXECUTE format('REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM %I', role_name);
    EXECUTE format('REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM %I', role_name);
  END LOOP;
END
\$production_authority_role_baseline\$;
GRANT SELECT ON TABLE
  public.model_provider_revisions,public.model_provider_revocations,
  public.model_tenant_provider_approvals,public.model_budget_accounts,
  public.model_gateway_requests,public.model_budget_reservations,
  public.model_stream_chunk_digests,public.model_execution_evidence,
  public.model_billing_usage_lines,public.model_billing_reconciliations,
  public.model_evidence_outbox,public.model_authority_evidence_outbox,
  public.model_data_governance_outbox TO $model_gateway_application_role;
GRANT INSERT ON TABLE
  public.model_gateway_requests,public.model_budget_reservations,
  public.model_stream_chunk_digests,public.model_execution_evidence,
  public.model_billing_usage_lines,public.model_billing_reconciliations,
  public.model_evidence_outbox,public.model_authority_evidence_outbox,
  public.model_data_governance_outbox TO $model_gateway_application_role;
GRANT UPDATE (reserved_microunits,spent_microunits,account_version,updated_at)
  ON public.model_budget_accounts TO $model_gateway_application_role;
GRANT UPDATE (state,owner_instance_id,lease_expires_at,selected_provider_key,
  provider_request_id,output_digest,output_artifact_ref,output_artifact_digest,
  safe_response,stable_error,evidence_ref,evidence_digest,updated_at,completed_at)
  ON public.model_gateway_requests TO $model_gateway_application_role;
GRANT UPDATE (actual_microunits,state,provider_key,provider_request_id,finalized_at)
  ON public.model_budget_reservations TO $model_gateway_application_role;
GRANT UPDATE (provider_statement_digest,reconciliation_state,reconciled_at)
  ON public.model_billing_usage_lines TO $model_gateway_application_role;
GRANT UPDATE (state,signed_receipt,evidence_ref,evidence_digest,updated_at,delivered_at)
  ON public.model_authority_evidence_outbox TO $model_gateway_application_role;
GRANT UPDATE (state,mutation_result,evidence_ref,evidence_digest,updated_at,completed_at)
  ON public.model_data_governance_outbox TO $model_gateway_application_role;
GRANT SELECT,INSERT ON TABLE
  public.data_resource_versions,public.data_authority_ingress,
  public.data_authority_executions,public.governed_data_labels,
  public.data_policy_decision_records,public.data_dlp_scan_summaries,
  public.data_transform_receipts,public.data_cross_domain_grants,
  public.data_cross_domain_consumptions,public.data_retention_records,
  public.data_legal_holds,public.data_export_intents,public.data_evidence_outbox
  TO $data_governance_application_role;
GRANT UPDATE (resource_version,action_hash,ledger_execution_id,fence_digest,updated_at)
  ON public.data_resource_versions TO $data_governance_application_role;
GRANT UPDATE (state,receipt,updated_at) ON public.data_authority_ingress TO $data_governance_application_role;
GRANT UPDATE (state,execution_owner,execution_lease_until,evidence_event_id,result,completed_at,updated_at)
  ON public.data_authority_executions TO $data_governance_application_role;
GRANT UPDATE (consumed_at,consumption_id) ON public.data_cross_domain_grants TO $data_governance_application_role;
GRANT UPDATE (state,released_at,release_approval_id,release_evidence_ref,release_evidence_digest,
  release_adapter_receipt,release_action_hash,release_ledger_execution_id)
  ON public.data_legal_holds TO $data_governance_application_role;
GRANT UPDATE (state,artifact_ref,artifact_digest,watermark_digest,signature_digest,
  worm_receipt_ref,worm_receipt_digest,completion_adapter_receipt,completed_at,
  completion_action_hash,completion_ledger_execution_id)
  ON public.data_export_intents TO $data_governance_application_role;
GRANT UPDATE (state,delivery_receipt,delivered_at) ON public.data_evidence_outbox TO $data_governance_application_role;
GRANT SELECT,INSERT ON TABLE
  public.governed_memory_entries,public.prompt_versions,public.knowledge_snapshots,
  public.context_knowledge_sources,public.context_deletion_tombstones,
  public.context_quarantine_records,public.context_resource_versions,
  public.context_action_ingress,public.context_authority_executions,
  public.context_retrieval_decisions,public.context_evidence_outbox
  TO $context_governance_application_role;
GRANT UPDATE (status,ledger_execution_id,fence_digest,resource_version,quarantine_reason_digest,updated_at)
  ON public.governed_memory_entries TO $context_governance_application_role;
GRANT UPDATE (status,rollout_percent,resource_version,activated_at,updated_at)
  ON public.prompt_versions TO $context_governance_application_role;
GRANT UPDATE (quarantined,resource_version,updated_at,index_ref,tombstoned)
  ON public.knowledge_snapshots TO $context_governance_application_role;
GRANT UPDATE (quarantined,resource_version,updated_at)
  ON public.context_knowledge_sources TO $context_governance_application_role;
GRANT UPDATE (released_by,remediation_evidence_ref,remediation_evidence_digest,released_at)
  ON public.context_quarantine_records TO $context_governance_application_role;
GRANT UPDATE (resource_version,action_hash,ledger_execution_id,fence_digest,updated_at)
  ON public.context_resource_versions TO $context_governance_application_role;
GRANT UPDATE (state,receipt,updated_at) ON public.context_action_ingress TO $context_governance_application_role;
GRANT UPDATE (state,external_receipts,safe_result,evidence_request,evidence_ref,evidence_digest,
  evidence_receipt,stable_error,execution_owner,execution_lease_until,updated_at)
  ON public.context_authority_executions TO $context_governance_application_role;
GRANT UPDATE (delivered_at) ON public.context_evidence_outbox TO $context_governance_application_role;
GRANT SELECT,INSERT ON TABLE
  public.runtime_anomaly_signal_sources,public.runtime_anomaly_trajectories,
  public.runtime_anomaly_signals,public.runtime_anomaly_findings,
  public.runtime_anomaly_aggregates,public.runtime_anomaly_baselines,
  public.runtime_anomaly_feedback,public.runtime_anomaly_cases,
  public.runtime_anomaly_action_ingress,public.runtime_anomaly_authority_executions,
  public.runtime_anomaly_response_commands,public.runtime_anomaly_evidence_events,
  public.runtime_anomaly_evidence_outbox TO $runtime_anomaly_application_role;
GRANT UPDATE ON TABLE public.runtime_anomaly_signal_sources,public.runtime_anomaly_trajectories,
  public.runtime_anomaly_cases,public.runtime_anomaly_action_ingress,
  public.runtime_anomaly_authority_executions,public.runtime_anomaly_response_commands,
  public.runtime_anomaly_evidence_outbox TO $runtime_anomaly_application_role;
GRANT SELECT,INSERT ON TABLE public.security_eval_datasets,public.security_eval_dataset_versions,
  public.attack_scenarios,public.security_campaigns,public.security_eval_campaign_scenarios,
  public.security_eval_scenario_results,public.security_findings,public.security_eval_remediations,
  public.security_eval_retests,public.security_eval_baselines,public.security_eval_reports,
  public.security_eval_kill_switches,public.security_eval_resource_versions,
  public.security_eval_action_ingress,public.security_eval_authority_executions,
  public.security_eval_evidence_outbox TO $security_evaluation_application_role;
GRANT INSERT ON TABLE public.security_eval_evidence_events TO $security_evaluation_application_role;
GRANT UPDATE ON TABLE public.security_eval_datasets,public.security_campaigns,public.security_findings,
  public.security_eval_remediations,public.security_eval_kill_switches,
  public.security_eval_resource_versions,public.security_eval_action_ingress,
  public.security_eval_authority_executions,public.security_eval_evidence_outbox
  TO $security_evaluation_application_role;
GRANT SELECT,INSERT,UPDATE ON TABLE public.supply_chain_publishers,
  public.supply_chain_publisher_keys,public.supply_chain_artifact_revisions,
  public.supply_chain_pack_releases,public.supply_chain_conformance_runs,
  public.supply_chain_pack_approvals,public.supply_chain_installations,
  public.supply_chain_revocations,public.supply_chain_authority_commands,
  public.supply_chain_evidence_events,public.supply_chain_evidence_outbox
  TO $pack_supply_chain_application_role;
GRANT SELECT,INSERT,UPDATE ON TABLE public.domain_pack_executions,
  public.domain_expert_approvals,public.domain_physical_supervision,
  public.domain_pack_evidence_outbox,public.coding_repository_resources,
  public.coding_execution_cases,public.industrial_asset_models,
  public.industrial_point_policies,public.industrial_setpoint_cases,
  public.industrial_telemetry_outcomes,public.industrial_stage_certifications,
  public.energy_assets,public.energy_forecast_snapshots,public.energy_dispatch_cases,
  public.energy_outcomes,public.energy_fallback_drills,public.medical_care_relationships,
  public.medical_access_decisions,public.medical_clinical_evidence,
  public.medical_human_reviews,public.medical_evaluation_findings,
  public.sensitive_consent_records,public.sensitive_conversation_cases,
  public.sensitive_source_citations,public.sensitive_human_escalations,
  public.sensitive_evaluation_findings TO $domain_runtime_application_role;
GRANT SELECT,INSERT ON TABLE public.sre_service_slos,public.sre_sli_observations,
  public.sre_burn_alerts,public.sre_incident_links,public.sre_deployment_topologies,
  public.sre_zone_health_observations,public.backup_manifests,public.sre_backup_artifacts,
  public.recovery_drills,public.sre_dr_plans,public.sre_dr_events,public.sre_chaos_campaigns,
  public.sre_chaos_results,public.sre_load_campaigns,public.sre_load_results,
  public.deployment_rollouts,public.sre_canary_observations,public.sre_cost_capacity_observations,
  public.sre_observability_evidence,public.sre_resource_versions,public.sre_action_ingress,
  public.sre_principal_assertion_replay,public.sre_authority_executions,public.sre_evidence_outbox
  TO $platform_sre_application_role;
GRANT UPDATE (service,sli_kind,window_seconds,target_millionths,minimum_samples,
  fast_burn_threshold_millionths,slow_burn_threshold_millionths,release_blocking,status,
  resource_version,updated_at) ON public.sre_service_slos TO $platform_sre_application_role;
GRANT UPDATE (deployment_mode,release_digest,topology_digest,zones,components,quorum_rules,
  disruption_budgets,immutable_image_digests,status,resource_version,updated_at)
  ON public.sre_deployment_topologies TO $platform_sre_application_role;
GRANT UPDATE (state,owner_subject,resolved_at,resource_version) ON public.sre_burn_alerts TO $platform_sre_application_role;
GRANT UPDATE (status,resource_version,updated_at) ON public.sre_dr_plans,public.sre_chaos_campaigns,public.sre_load_campaigns TO $platform_sre_application_role;
GRANT UPDATE (status,current_canary_percent,resource_version,updated_at) ON public.deployment_rollouts TO $platform_sre_application_role;
GRANT UPDATE (resource_version,action_hash,ledger_execution_id,ledger_event_id,ledger_event_digest,fence_digest,updated_at)
  ON public.sre_resource_versions TO $platform_sre_application_role;
GRANT UPDATE (state,receipt,updated_at) ON public.sre_action_ingress TO $platform_sre_application_role;
GRANT UPDATE (state,execution_owner,lease_expires_at,external_receipt,safe_result,evidence_request,evidence_ref,evidence_digest,updated_at)
  ON public.sre_authority_executions TO $platform_sre_application_role;
GRANT UPDATE (delivered_at,delivery_attempts) ON public.sre_evidence_outbox TO $platform_sre_application_role;
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
  column_name text;
  enterprise_tables constant text[] := ARRAY[
    'enterprise_remote_actions', 'enterprise_approval_intents',
    'spring_session', 'spring_session_attributes'
  ];
  enterprise_authority_tables constant text[] := ARRAY[
    'enterprise_principal_assertion_replay', 'enterprise_action_ingress',
    'enterprise_resource_versions', 'enterprise_authority_executions',
    'enterprise_authority_outbox', 'enterprise_tenants', 'enterprise_organizations',
    'enterprise_projects', 'enterprise_integrations', 'enterprise_quota_usage',
    'enterprise_cost_usage', 'enterprise_api_keys', 'enterprise_admin_actions'
  ];
  orchestrator_tables constant text[] := ARRAY[
    'orchestrator_ingress_actions', 'orchestrator_stream_events'
  ];
  execution_tables constant text[] := ARRAY[
    'orchestrator_ingress_actions', 'tool_versions', 'registry_snapshots', 'executions',
    'idempotency_records', 'execution_outbox'
  ];
  registry_tables constant text[] := ARRAY[
    'tools', 'tool_versions', 'tool_signatures', 'registry_events',
    'registry_snapshots', 'registry_publisher_keys', 'registry_tenant_revisions',
    'registry_idempotency_records', 'executor_profiles', 'credential_profiles',
    'approval_profiles', 'capabilities', 'capability_versions'
  ];
  agent_registry_tables constant text[] := ARRAY[
    'agent_assets', 'agent_discovery_facts', 'agent_posture_findings', 'agent_boms',
    'agent_ownership_confirmations', 'agent_relationship_edges',
    'agent_relationship_supersessions', 'agent_posture_resolutions',
    'agent_lifecycle_records', 'agent_registry_idempotency',
    'agent_registry_audit_heads', 'agent_registry_audit_events', 'agent_registry_outbox'
  ];
  policy_admin_tables constant text[] := ARRAY[
    'policy_sources', 'policy_analysis_results', 'policy_simulation_runs',
    'policy_impact_reports', 'policy_reviews', 'policy_bundles', 'policy_exceptions',
    'policy_promotions', 'policy_activation_intents', 'policy_resource_versions',
    'policy_principal_assertion_replay',
    'policy_action_ingress', 'policy_authority_executions', 'policy_evidence_events',
    'policy_evidence_outbox'
  ];
  incident_release_tables constant text[] := ARRAY[
    'incidents', 'replay_runs', 'incident_principal_assertion_replay',
    'incident_action_ingress', 'incident_resource_versions',
    'incident_authority_executions', 'incident_timeline', 'containment_actions',
    'incident_evidence_preservations', 'replay_plans', 'root_cause_reports',
    'incident_recertifications', 'release_gate_runs', 'release_gate_certificates',
    'release_canary_events', 'incident_evidence_events', 'incident_evidence_outbox'
  ];
  pack_marketplace_tables constant text[] := ARRAY[
    'marketplace_publishers', 'marketplace_publisher_keys', 'marketplace_pack_names',
    'marketplace_tenant_catalog', 'marketplace_releases', 'marketplace_installations',
    'marketplace_upgrade_plans', 'marketplace_canary_results', 'marketplace_revocations',
    'marketplace_resource_versions', 'marketplace_principal_assertion_replay',
    'marketplace_action_ingress', 'marketplace_authority_executions',
    'marketplace_evidence_events', 'marketplace_evidence_outbox'
  ];
  approval_tables constant text[] := ARRAY[
    'approval_cases', 'approval_decisions', 'approval_grants',
    'approval_notification_outbox', 'approval_consumptions',
    'approval_mutation_receipts', 'approval_principal_assertion_uses', 'approval_events',
    'approval_decision_evidence_receipts', 'approval_decision_evidence_outbox'
  ];
  pep_tables constant text[] := ARRAY[
    'pep_authorization_requests', 'pep_policy_decisions',
    'pep_execution_authorizations', 'pep_human_assertion_uses',
    'pep_governance_evidence', 'pep_evidence_outbox',
    'pep_policy_bundle_artifacts', 'pep_policy_activation_requests',
    'pep_active_policy_bundles', 'pep_policy_activation_evidence',
    'pep_policy_activation_outbox'
  ];
  identity_tables constant text[] := ARRAY[
    'agent_principals', 'credential_profiles', 'credential_handles',
    'identity_revocations', 'identity_tenant_epochs', 'identity_task_lifecycle',
    'identity_credential_signing_keys', 'identity_credential_idempotency',
    'identity_credential_events', 'identity_credential_outbox'
  ];
  tool_proxy_tables constant text[] := ARRAY[
    'tool_proxy_invocations', 'tool_proxy_audit_events', 'tool_proxy_outbox'
  ];
  evidence_tables constant text[] := ARRAY[
    'audit_events', 'evidence_chain_heads', 'execution_evidence_receipts',
    'evidence_artifacts', 'evidence_artifact_requests', 'evidence_event_requests',
    'authority_evidence_event_requests',
    'evidence_packages',
    'evidence_package_requests', 'evaluation_results', 'evidence_outbox',
    'executions', 'pep_execution_authorizations', 'orchestrator_tasks',
    'orchestrator_ingress_actions'
  ];
  audit_tables constant text[] := ARRAY[
    'audit_records', 'audit_chain_heads', 'audit_retention_policies', 'legal_holds',
    'audit_export_manifests', 'audit_deletion_proofs', 'audit_operation_replays',
    'audit_retention_outbox', 'audit_human_assertion_uses', 'audit_control_definitions',
    'audit_evidence_nodes',
    'audit_evidence_edges'
  ];
BEGIN
  FOREACH table_name IN ARRAY enterprise_tables LOOP
    IF to_regclass(format('public.%I', table_name)) IS NULL THEN
      RAISE EXCEPTION 'MIGRATION_ENTERPRISE_TABLE_MISSING:%', table_name;
    END IF;
    IF table_name IN ('spring_session', 'spring_session_attributes') THEN
      FOREACH privilege_name IN ARRAY ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE'] LOOP
        IF NOT has_table_privilege(
          '$enterprise_application_role', format('public.%I', table_name), privilege_name
        ) THEN
          RAISE EXCEPTION 'MIGRATION_ENTERPRISE_SESSION_GRANT_MISSING:%.%',
            table_name, privilege_name;
        END IF;
      END LOOP;
    ELSIF NOT has_table_privilege(
      '$enterprise_application_role', format('public.%I', table_name), 'SELECT'
    ) OR NOT has_table_privilege(
      '$enterprise_application_role', format('public.%I', table_name), 'INSERT'
    ) OR has_table_privilege(
      '$enterprise_application_role', format('public.%I', table_name),
      'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
    ) THEN
      RAISE EXCEPTION 'MIGRATION_ENTERPRISE_QUEUE_GRANTS_INVALID:%', table_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY[
    'status','response_payload','evidence_ref','attempts','next_attempt_at',
    'last_error_code','updated_at'
  ] LOOP
    IF NOT has_column_privilege(
      '$enterprise_application_role', 'public.enterprise_remote_actions', column_name, 'UPDATE'
    ) THEN
      RAISE EXCEPTION 'MIGRATION_ENTERPRISE_REMOTE_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY[
    'status','response_payload','evidence_ref','attempts','next_attempt_at',
    'last_error_code','updated_at'
  ] LOOP
    IF NOT has_column_privilege(
      '$enterprise_application_role', 'public.enterprise_approval_intents', column_name, 'UPDATE'
    ) THEN
      RAISE EXCEPTION 'MIGRATION_ENTERPRISE_APPROVAL_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  IF EXISTS (
    SELECT 1 FROM information_schema.column_privileges AS column_grant
     WHERE column_grant.table_schema='public'
       AND column_grant.grantee='$enterprise_application_role'
       AND column_grant.privilege_type='UPDATE'
       AND (
         (column_grant.table_name='enterprise_remote_actions'
          AND column_grant.column_name NOT IN (
           'status','response_payload','evidence_ref','attempts','next_attempt_at',
           'last_error_code','updated_at'
         )) OR
         (column_grant.table_name='enterprise_approval_intents'
          AND column_grant.column_name NOT IN (
           'status','response_payload','evidence_ref','attempts','next_attempt_at',
           'last_error_code','updated_at'
         )) OR
         column_grant.table_name NOT IN (
           'enterprise_remote_actions','enterprise_approval_intents',
           'spring_session','spring_session_attributes'
         )
       )
  ) THEN
    RAISE EXCEPTION 'MIGRATION_ENTERPRISE_EXCESS_COLUMN_UPDATE_GRANT';
  END IF;
  FOREACH table_name IN ARRAY enterprise_authority_tables LOOP
    IF to_regclass(format('public.%I', table_name)) IS NULL THEN
      RAISE EXCEPTION 'MIGRATION_ENTERPRISE_AUTHORITY_TABLE_MISSING:%', table_name;
    END IF;
    IF table_name = 'enterprise_authority_outbox' THEN
      IF NOT has_table_privilege(
        '$enterprise_authority_application_role', format('public.%I', table_name), 'INSERT'
      ) OR has_table_privilege(
        '$enterprise_authority_application_role', format('public.%I', table_name),
        'SELECT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
      ) THEN
        RAISE EXCEPTION 'MIGRATION_ENTERPRISE_AUTHORITY_OUTBOX_GRANTS_INVALID';
      END IF;
    ELSIF NOT has_table_privilege(
      '$enterprise_authority_application_role', format('public.%I', table_name), 'SELECT'
    ) OR NOT has_table_privilege(
      '$enterprise_authority_application_role', format('public.%I', table_name), 'INSERT'
    ) OR has_table_privilege(
      '$enterprise_authority_application_role', format('public.%I', table_name),
      'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
    ) THEN
      RAISE EXCEPTION 'MIGRATION_ENTERPRISE_AUTHORITY_GRANTS_INVALID:%', table_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY['state','receipt','updated_at'] LOOP
    IF NOT has_column_privilege(
      '$enterprise_authority_application_role', 'public.enterprise_action_ingress',
      column_name, 'UPDATE'
    ) THEN
      RAISE EXCEPTION 'MIGRATION_ENTERPRISE_AUTHORITY_INGRESS_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY[
    'resource_version','action_hash','ledger_execution_id','fence_digest','updated_at'
  ] LOOP
    IF NOT has_column_privilege(
      '$enterprise_authority_application_role', 'public.enterprise_resource_versions',
      column_name, 'UPDATE'
    ) THEN
      RAISE EXCEPTION 'MIGRATION_ENTERPRISE_AUTHORITY_VERSION_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY[
    'state','safe_result','safe_result_digest','stable_error','updated_at'
  ] LOOP
    IF NOT has_column_privilege(
      '$enterprise_authority_application_role', 'public.enterprise_authority_executions',
      column_name, 'UPDATE'
    ) THEN
      RAISE EXCEPTION 'MIGRATION_ENTERPRISE_AUTHORITY_EXECUTION_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY['used','limit_value'] LOOP
    IF NOT has_column_privilege(
      '$enterprise_authority_application_role', 'public.enterprise_quota_usage',
      column_name, 'UPDATE'
    ) THEN
      RAISE EXCEPTION 'MIGRATION_ENTERPRISE_AUTHORITY_QUOTA_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY['revoked_at','revocation_reason'] LOOP
    IF NOT has_column_privilege(
      '$enterprise_authority_application_role', 'public.enterprise_api_keys',
      column_name, 'UPDATE'
    ) THEN
      RAISE EXCEPTION 'MIGRATION_ENTERPRISE_AUTHORITY_API_KEY_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  IF EXISTS (
    SELECT 1 FROM information_schema.column_privileges AS column_grant
     WHERE column_grant.table_schema='public'
       AND column_grant.grantee='$enterprise_authority_application_role'
       AND column_grant.privilege_type='UPDATE'
       AND NOT (
         (column_grant.table_name='enterprise_action_ingress'
          AND column_grant.column_name IN ('state','receipt','updated_at')) OR
         (column_grant.table_name='enterprise_resource_versions'
          AND column_grant.column_name IN (
           'resource_version','action_hash','ledger_execution_id','fence_digest','updated_at'
         )) OR
         (column_grant.table_name='enterprise_authority_executions'
          AND column_grant.column_name IN (
           'state','safe_result','safe_result_digest','stable_error','updated_at'
         )) OR
         (column_grant.table_name='enterprise_quota_usage'
          AND column_grant.column_name IN ('used','limit_value')) OR
         (column_grant.table_name='enterprise_api_keys'
          AND column_grant.column_name IN ('revoked_at','revocation_reason'))
       )
  ) THEN
    RAISE EXCEPTION 'MIGRATION_ENTERPRISE_AUTHORITY_EXCESS_COLUMN_UPDATE_GRANT';
  END IF;
  FOREACH table_name IN ARRAY orchestrator_tables LOOP
    IF to_regclass(format('public.%I', table_name)) IS NULL THEN
      RAISE EXCEPTION 'MIGRATION_ORCHESTRATOR_TABLE_MISSING:%', table_name;
    END IF;
    FOREACH privilege_name IN ARRAY ARRAY['SELECT', 'INSERT'] LOOP
      IF NOT has_table_privilege(
        '$orchestrator_application_role', format('public.%I', table_name), privilege_name
      ) THEN
        RAISE EXCEPTION 'MIGRATION_ORCHESTRATOR_GRANT_MISSING:%.%', table_name, privilege_name;
      END IF;
    END LOOP;
  END LOOP;
  IF has_table_privilege(
       '$orchestrator_application_role', 'public.orchestrator_ingress_actions', 'UPDATE,DELETE'
     )
     OR has_table_privilege(
       '$orchestrator_application_role', 'public.orchestrator_stream_events', 'UPDATE,DELETE'
     )
     OR EXISTS (
       SELECT 1 FROM information_schema.column_privileges AS column_grant
        WHERE column_grant.table_schema = 'public'
          AND column_grant.grantee = '$orchestrator_application_role'
          AND column_grant.privilege_type = 'UPDATE'
          AND NOT (
            column_grant.table_name = 'orchestrator_ingress_actions'
            AND column_grant.column_name IN ('status', 'updated_at')
          )
     )
  THEN
    RAISE EXCEPTION 'MIGRATION_ORCHESTRATOR_EXCESS_MUTATION_GRANT';
  END IF;
  FOREACH column_name IN ARRAY ARRAY['status', 'updated_at'] LOOP
    IF NOT has_column_privilege(
      '$orchestrator_application_role', 'public.orchestrator_ingress_actions',
      column_name, 'UPDATE'
    ) THEN
      RAISE EXCEPTION 'MIGRATION_ORCHESTRATOR_UPDATE_GRANT_MISSING:%', column_name;
    END IF;
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
  FOREACH table_name IN ARRAY pep_tables LOOP
    IF to_regclass(format('public.%I', table_name)) IS NULL
       OR NOT has_table_privilege(
         '$pep_application_role', format('public.%I', table_name), 'SELECT'
       )
       OR NOT has_table_privilege(
         '$pep_application_role', format('public.%I', table_name), 'INSERT'
       )
       OR (
         table_name = 'pep_authorization_requests'
         AND NOT has_table_privilege(
           '$pep_application_role', format('public.%I', table_name), 'UPDATE'
         )
       )
       OR (
         table_name <> 'pep_authorization_requests'
         AND has_table_privilege(
           '$pep_application_role', format('public.%I', table_name), 'UPDATE'
         )
       )
       OR has_table_privilege(
         '$pep_application_role', format('public.%I', table_name),
         'DELETE,TRUNCATE,REFERENCES,TRIGGER'
       ) THEN
      RAISE EXCEPTION 'MIGRATION_PEP_GRANTS_INVALID:%', table_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY[
    'state','claim_owner','claim_expires_at','pdp_ack_digest','pdp_ack_body',
    'response_digest','response_body','completed_at','updated_at'
  ] LOOP
    IF NOT has_column_privilege(
      '$pep_application_role', 'public.pep_policy_activation_requests',
      column_name, 'UPDATE'
    ) THEN RAISE EXCEPTION 'MIGRATION_PEP_ACTIVATION_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY[
    'activation_id','policy_id','sequence','bundle_digest','policy_version',
    'pdp_ack_digest','activated_at'
  ] LOOP
    IF NOT has_column_privilege(
      '$pep_application_role', 'public.pep_active_policy_bundles', column_name, 'UPDATE'
    ) THEN RAISE EXCEPTION 'MIGRATION_PEP_ACTIVE_BUNDLE_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  IF EXISTS (
    SELECT 1 FROM information_schema.column_privileges AS column_grant
     WHERE column_grant.table_schema='public'
       AND column_grant.grantee='$pep_application_role'
       AND column_grant.privilege_type='UPDATE'
       AND column_grant.table_name <> 'pep_authorization_requests'
       AND NOT (
         (column_grant.table_name='pep_policy_activation_requests'
          AND column_grant.column_name IN (
           'state','claim_owner','claim_expires_at','pdp_ack_digest','pdp_ack_body',
           'response_digest','response_body','completed_at','updated_at'
         )) OR
         (column_grant.table_name='pep_active_policy_bundles'
          AND column_grant.column_name IN (
           'activation_id','policy_id','sequence','bundle_digest','policy_version',
           'pdp_ack_digest','activated_at'
         ))
       )
  ) THEN
    RAISE EXCEPTION 'MIGRATION_PEP_EXCESS_COLUMN_UPDATE_GRANT';
  END IF;
  FOREACH table_name IN ARRAY approval_tables LOOP
    IF to_regclass(format('public.%I', table_name)) IS NULL
       OR NOT has_table_privilege(
         '$approval_application_role', format('public.%I', table_name), 'SELECT'
       )
       OR NOT has_table_privilege(
         '$approval_application_role', format('public.%I', table_name), 'INSERT'
       )
       OR has_table_privilege(
         '$approval_application_role', format('public.%I', table_name),
         'DELETE,TRUNCATE,REFERENCES,TRIGGER'
       ) THEN
      RAISE EXCEPTION 'MIGRATION_APPROVAL_GRANTS_INVALID:%', table_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY['status', 'updated_at'] LOOP
    IF NOT has_column_privilege(
      '$approval_application_role', 'public.approval_cases', column_name, 'UPDATE'
    ) THEN
      RAISE EXCEPTION 'MIGRATION_APPROVAL_CASE_UPDATE_GRANT_MISSING:%', column_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY[
    'remaining_uses', 'revoked_at', 'revoked_by', 'revocation_reason_digest',
    'revocation_receipt', 'last_consumed_at'
  ] LOOP
    IF NOT has_column_privilege(
      '$approval_application_role', 'public.approval_grants', column_name, 'UPDATE'
    ) THEN
      RAISE EXCEPTION 'MIGRATION_APPROVAL_GRANT_UPDATE_GRANT_MISSING:%', column_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY[
    'delivery_attempts', 'next_attempt_at', 'lease_owner', 'lease_expires_at',
    'last_attempt_at', 'last_error_code', 'signed_authority_receipt', 'delivered_at'
  ] LOOP
    IF NOT has_column_privilege(
      '$approval_application_role', 'public.approval_decision_evidence_outbox',
      column_name, 'UPDATE'
    ) THEN
      RAISE EXCEPTION 'MIGRATION_APPROVAL_EVIDENCE_OUTBOX_UPDATE_GRANT_MISSING:%',
        column_name;
    END IF;
  END LOOP;
  IF EXISTS (
    SELECT 1
      FROM information_schema.columns AS columns
     WHERE columns.table_schema = 'public'
       AND columns.table_name = ANY (approval_tables)
       AND NOT (
         (columns.table_name = 'approval_cases'
          AND columns.column_name = ANY (ARRAY['status', 'updated_at']))
         OR
         (columns.table_name = 'approval_grants'
          AND columns.column_name = ANY (ARRAY[
            'remaining_uses', 'revoked_at', 'revoked_by', 'revocation_reason_digest',
            'revocation_receipt', 'last_consumed_at'
          ]))
         OR
         (columns.table_name = 'approval_decision_evidence_outbox'
          AND columns.column_name = ANY (ARRAY[
            'delivery_attempts', 'next_attempt_at', 'lease_owner', 'lease_expires_at',
            'last_attempt_at', 'last_error_code', 'signed_authority_receipt', 'delivered_at'
          ]))
       )
       AND has_column_privilege(
         '$approval_application_role',
         format('public.%I', columns.table_name), columns.column_name, 'UPDATE'
       )
  ) THEN
    RAISE EXCEPTION 'MIGRATION_APPROVAL_EXCESS_COLUMN_UPDATE_GRANT';
  END IF;
  FOREACH table_name IN ARRAY identity_tables LOOP
    IF to_regclass(format('public.%I', table_name)) IS NULL
       OR has_table_privilege(
         '$identity_application_role', format('public.%I', table_name),
         'DELETE,TRUNCATE,REFERENCES,TRIGGER'
       ) THEN
      RAISE EXCEPTION 'MIGRATION_IDENTITY_GRANTS_INVALID:%', table_name;
    END IF;
  END LOOP;
  FOREACH table_name IN ARRAY ARRAY[
    'agent_principals', 'credential_profiles', 'identity_credential_signing_keys'
  ] LOOP
    IF NOT has_table_privilege(
         '$identity_application_role', format('public.%I', table_name), 'SELECT'
       )
       OR has_table_privilege(
         '$identity_application_role', format('public.%I', table_name), 'INSERT,UPDATE'
       ) THEN
      RAISE EXCEPTION 'MIGRATION_IDENTITY_READ_ONLY_GRANTS_INVALID:%', table_name;
    END IF;
  END LOOP;
  FOREACH table_name IN ARRAY ARRAY[
    'credential_handles', 'identity_tenant_epochs', 'identity_task_lifecycle'
  ] LOOP
    FOREACH privilege_name IN ARRAY ARRAY['SELECT', 'INSERT', 'UPDATE'] LOOP
      IF NOT has_table_privilege(
        '$identity_application_role', format('public.%I', table_name), privilege_name
      ) THEN
        RAISE EXCEPTION 'MIGRATION_IDENTITY_MUTABLE_GRANT_MISSING:%.%',
          table_name, privilege_name;
      END IF;
    END LOOP;
  END LOOP;
  FOREACH table_name IN ARRAY ARRAY[
    'identity_revocations', 'identity_credential_idempotency'
  ] LOOP
    IF NOT has_table_privilege(
         '$identity_application_role', format('public.%I', table_name), 'SELECT'
       )
       OR NOT has_table_privilege(
         '$identity_application_role', format('public.%I', table_name), 'INSERT'
       )
       OR has_table_privilege(
         '$identity_application_role', format('public.%I', table_name), 'UPDATE'
       ) THEN
      RAISE EXCEPTION 'MIGRATION_IDENTITY_APPEND_GRANTS_INVALID:%', table_name;
    END IF;
  END LOOP;
  FOREACH table_name IN ARRAY ARRAY[
    'identity_credential_events', 'identity_credential_outbox'
  ] LOOP
    IF NOT has_table_privilege(
         '$identity_application_role', format('public.%I', table_name), 'INSERT'
       )
       OR has_table_privilege(
         '$identity_application_role', format('public.%I', table_name), 'SELECT,UPDATE'
       ) THEN
      RAISE EXCEPTION 'MIGRATION_IDENTITY_WRITE_ONLY_GRANTS_INVALID:%', table_name;
    END IF;
  END LOOP;
  FOREACH table_name IN ARRAY tool_proxy_tables LOOP
    IF to_regclass(format('public.%I', table_name)) IS NULL
       OR has_table_privilege(
         '$tool_proxy_application_role', format('public.%I', table_name),
         'DELETE,TRUNCATE,REFERENCES,TRIGGER'
       ) THEN
      RAISE EXCEPTION 'MIGRATION_TOOL_PROXY_GRANTS_INVALID:%', table_name;
    END IF;
  END LOOP;
  FOREACH privilege_name IN ARRAY ARRAY['SELECT', 'INSERT', 'UPDATE'] LOOP
    IF NOT has_table_privilege(
      '$tool_proxy_application_role', 'public.tool_proxy_invocations', privilege_name
    ) THEN
      RAISE EXCEPTION 'MIGRATION_TOOL_PROXY_INVOCATION_GRANT_MISSING:%', privilege_name;
    END IF;
  END LOOP;
  FOREACH table_name IN ARRAY ARRAY['tool_proxy_audit_events', 'tool_proxy_outbox'] LOOP
    IF NOT has_table_privilege(
         '$tool_proxy_application_role', format('public.%I', table_name), 'INSERT'
       )
       OR has_table_privilege(
         '$tool_proxy_application_role', format('public.%I', table_name), 'SELECT,UPDATE'
       ) THEN
      RAISE EXCEPTION 'MIGRATION_TOOL_PROXY_WRITE_ONLY_GRANTS_INVALID:%', table_name;
    END IF;
  END LOOP;
  FOREACH table_name IN ARRAY evidence_tables LOOP
    IF to_regclass(format('public.%I', table_name)) IS NULL
       OR has_table_privilege(
         '$evidence_application_role', format('public.%I', table_name),
         'DELETE,TRUNCATE,REFERENCES,TRIGGER'
       ) THEN
      RAISE EXCEPTION 'MIGRATION_EVIDENCE_GRANTS_INVALID:%', table_name;
    END IF;
  END LOOP;
  FOREACH table_name IN ARRAY ARRAY[
    'audit_events', 'execution_evidence_receipts', 'evidence_artifacts',
    'evidence_artifact_requests', 'evidence_event_requests',
    'authority_evidence_event_requests', 'evidence_packages',
    'evidence_package_requests',
    'evaluation_results', 'evidence_outbox'
  ] LOOP
    IF NOT has_table_privilege(
         '$evidence_application_role', format('public.%I', table_name), 'SELECT'
       )
       OR NOT has_table_privilege(
         '$evidence_application_role', format('public.%I', table_name), 'INSERT'
       )
       OR has_table_privilege(
         '$evidence_application_role', format('public.%I', table_name), 'UPDATE'
       ) THEN
      RAISE EXCEPTION 'MIGRATION_EVIDENCE_APPEND_GRANTS_INVALID:%', table_name;
    END IF;
  END LOOP;
  FOREACH privilege_name IN ARRAY ARRAY['SELECT', 'INSERT', 'UPDATE'] LOOP
    IF NOT has_table_privilege(
      '$evidence_application_role', 'public.evidence_chain_heads', privilege_name
    ) THEN
      RAISE EXCEPTION 'MIGRATION_EVIDENCE_CHAIN_GRANT_MISSING:%', privilege_name;
    END IF;
  END LOOP;
  FOREACH table_name IN ARRAY ARRAY[
    'executions', 'pep_execution_authorizations', 'orchestrator_tasks',
    'orchestrator_ingress_actions'
  ] LOOP
    IF NOT has_table_privilege(
         '$evidence_application_role', format('public.%I', table_name), 'SELECT'
       )
       OR has_table_privilege(
         '$evidence_application_role', format('public.%I', table_name), 'INSERT,UPDATE'
       ) THEN
      RAISE EXCEPTION 'MIGRATION_EVIDENCE_LEDGER_READ_GRANTS_INVALID:%', table_name;
    END IF;
  END LOOP;
  FOREACH table_name IN ARRAY audit_tables LOOP
    IF to_regclass(format('public.%I', table_name)) IS NULL
       OR NOT has_table_privilege(
         '$audit_application_role', format('public.%I', table_name), 'SELECT'
       )
       OR NOT has_table_privilege(
         '$audit_application_role', format('public.%I', table_name), 'INSERT'
       )
       OR has_table_privilege(
         '$audit_application_role', format('public.%I', table_name),
         'DELETE,TRUNCATE,REFERENCES,TRIGGER'
       )
       OR (
         table_name = 'audit_chain_heads'
         AND NOT has_table_privilege(
           '$audit_application_role', format('public.%I', table_name), 'UPDATE'
         )
       )
       OR (
         table_name <> 'audit_chain_heads'
         AND has_table_privilege(
           '$audit_application_role', format('public.%I', table_name), 'UPDATE'
         )
       ) THEN
      RAISE EXCEPTION 'MIGRATION_AUDIT_GRANTS_INVALID:%', table_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY['released_by', 'released_at', 'release_reason'] LOOP
    IF NOT has_column_privilege(
      '$audit_application_role', 'public.legal_holds', column_name, 'UPDATE'
    ) THEN
      RAISE EXCEPTION 'MIGRATION_AUDIT_LEGAL_HOLD_GRANT_MISSING:%', column_name;
    END IF;
  END LOOP;
  IF EXISTS (
    SELECT 1 FROM information_schema.column_privileges AS column_grant
     WHERE column_grant.table_schema='public'
       AND column_grant.table_name='legal_holds'
       AND column_grant.grantee='$audit_application_role'
       AND column_grant.privilege_type='UPDATE'
       AND column_grant.column_name NOT IN ('released_by','released_at','release_reason')
  ) THEN
    RAISE EXCEPTION 'MIGRATION_AUDIT_LEGAL_HOLD_EXCESS_GRANT';
  END IF;
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
  FOREACH table_name IN ARRAY registry_tables LOOP
    IF to_regclass(format('public.%I', table_name)) IS NULL THEN
      RAISE EXCEPTION 'MIGRATION_REGISTRY_TABLE_MISSING:%', table_name;
    END IF;
    IF NOT has_table_privilege(
      '$registry_application_role', format('public.%I', table_name), 'SELECT'
    ) THEN
      RAISE EXCEPTION 'MIGRATION_REGISTRY_GRANT_MISSING:%.SELECT', table_name;
    END IF;
    IF has_table_privilege(
      '$registry_application_role', format('public.%I', table_name),
      'DELETE,TRUNCATE,REFERENCES,TRIGGER'
    ) THEN
      RAISE EXCEPTION 'MIGRATION_REGISTRY_EXCESS_GRANT:%', table_name;
    END IF;
  END LOOP;
  FOREACH table_name IN ARRAY ARRAY[
    'tools','tool_versions','tool_signatures','registry_events','registry_snapshots',
    'registry_publisher_keys','registry_tenant_revisions','registry_idempotency_records'
  ] LOOP
    IF NOT has_table_privilege(
      '$registry_application_role', format('public.%I', table_name), 'INSERT'
    ) THEN
      RAISE EXCEPTION 'MIGRATION_REGISTRY_GRANT_MISSING:%.INSERT', table_name;
    END IF;
  END LOOP;
  FOREACH table_name IN ARRAY ARRAY[
    'tool_versions','registry_publisher_keys','registry_tenant_revisions'
  ] LOOP
    IF NOT has_table_privilege(
      '$registry_application_role', format('public.%I', table_name), 'UPDATE'
    ) THEN
      RAISE EXCEPTION 'MIGRATION_REGISTRY_GRANT_MISSING:%.UPDATE', table_name;
    END IF;
  END LOOP;
  IF has_table_privilege('$registry_application_role','public.tools','UPDATE')
     OR has_table_privilege('$registry_application_role','public.tool_signatures','UPDATE')
     OR has_table_privilege('$registry_application_role','public.registry_events','UPDATE')
     OR has_table_privilege('$registry_application_role','public.registry_snapshots','UPDATE')
     OR has_table_privilege('$registry_application_role','public.registry_idempotency_records','UPDATE')
     OR has_table_privilege('$registry_application_role','public.executor_profiles','INSERT,UPDATE')
     OR has_table_privilege('$registry_application_role','public.credential_profiles','INSERT,UPDATE')
     OR has_table_privilege('$registry_application_role','public.approval_profiles','INSERT,UPDATE')
     OR has_table_privilege('$registry_application_role','public.capabilities','INSERT,UPDATE')
     OR has_table_privilege('$registry_application_role','public.capability_versions','INSERT,UPDATE') THEN
    RAISE EXCEPTION 'MIGRATION_REGISTRY_EXCESS_WRITE_GRANT';
  END IF;
  FOREACH table_name IN ARRAY agent_registry_tables LOOP
    IF to_regclass(format('public.%I', table_name)) IS NULL
       OR NOT has_table_privilege(
         '$agent_registry_application_role', format('public.%I', table_name), 'SELECT'
       )
       OR NOT has_table_privilege(
         '$agent_registry_application_role', format('public.%I', table_name), 'INSERT'
       )
       OR has_table_privilege(
         '$agent_registry_application_role', format('public.%I', table_name),
         'DELETE,TRUNCATE,REFERENCES,TRIGGER'
       )
       OR (
         table_name IN ('agent_assets','agent_registry_audit_heads')
         AND NOT has_table_privilege(
           '$agent_registry_application_role', format('public.%I', table_name), 'UPDATE'
         )
       )
       OR (
         table_name NOT IN ('agent_assets','agent_registry_audit_heads')
         AND has_table_privilege(
           '$agent_registry_application_role', format('public.%I', table_name), 'UPDATE'
         )
       ) THEN
      RAISE EXCEPTION 'MIGRATION_AGENT_REGISTRY_GRANTS_INVALID:%', table_name;
    END IF;
  END LOOP;
  FOREACH table_name IN ARRAY policy_admin_tables LOOP
    IF to_regclass(format('public.%I', table_name)) IS NULL THEN
      RAISE EXCEPTION 'MIGRATION_POLICY_ADMIN_TABLE_MISSING:%', table_name;
    END IF;
    IF table_name = 'policy_evidence_outbox' THEN
      IF NOT has_table_privilege(
        '$policy_admin_application_role', format('public.%I', table_name), 'INSERT'
      ) OR has_table_privilege(
        '$policy_admin_application_role', format('public.%I', table_name),
        'SELECT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
      ) THEN
        RAISE EXCEPTION 'MIGRATION_POLICY_ADMIN_OUTBOX_GRANTS_INVALID';
      END IF;
    ELSIF NOT has_table_privilege(
      '$policy_admin_application_role', format('public.%I', table_name), 'SELECT'
    ) OR NOT has_table_privilege(
      '$policy_admin_application_role', format('public.%I', table_name), 'INSERT'
    ) OR has_table_privilege(
      '$policy_admin_application_role', format('public.%I', table_name),
      'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
    ) THEN
      RAISE EXCEPTION 'MIGRATION_POLICY_ADMIN_GRANTS_INVALID:%', table_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY['lifecycle_state','updated_at'] LOOP
    IF NOT has_column_privilege(
      '$policy_admin_application_role', 'public.policy_sources', column_name, 'UPDATE'
    ) THEN RAISE EXCEPTION 'MIGRATION_POLICY_ADMIN_SOURCE_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY['status','deprecated_at'] LOOP
    IF NOT has_column_privilege(
      '$policy_admin_application_role', 'public.policy_bundles', column_name, 'UPDATE'
    ) THEN RAISE EXCEPTION 'MIGRATION_POLICY_ADMIN_BUNDLE_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY['revoked_at','revocation_reason_digest','expired_at'] LOOP
    IF NOT has_column_privilege(
      '$policy_admin_application_role', 'public.policy_exceptions', column_name, 'UPDATE'
    ) THEN RAISE EXCEPTION 'MIGRATION_POLICY_ADMIN_EXCEPTION_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY['state','completed_at'] LOOP
    IF NOT has_column_privilege(
      '$policy_admin_application_role', 'public.policy_promotions', column_name, 'UPDATE'
    ) THEN RAISE EXCEPTION 'MIGRATION_POLICY_ADMIN_PROMOTION_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY[
    'state','claim_owner','claim_expires_at','acknowledgement_digest',
    'acknowledgement','updated_at','activated_at'
  ] LOOP
    IF NOT has_column_privilege(
      '$policy_admin_application_role', 'public.policy_activation_intents',
      column_name, 'UPDATE'
    ) THEN
      RAISE EXCEPTION 'MIGRATION_POLICY_ADMIN_ACTIVATION_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY[
    'resource_version','action_hash','ledger_execution_id','fence_digest','updated_at'
  ] LOOP
    IF NOT has_column_privilege(
      '$policy_admin_application_role', 'public.policy_resource_versions', column_name, 'UPDATE'
    ) THEN RAISE EXCEPTION 'MIGRATION_POLICY_ADMIN_VERSION_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY['state','receipt','updated_at'] LOOP
    IF NOT has_column_privilege(
      '$policy_admin_application_role', 'public.policy_action_ingress', column_name, 'UPDATE'
    ) THEN RAISE EXCEPTION 'MIGRATION_POLICY_ADMIN_INGRESS_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY[
    'state','safe_result','safe_result_digest','stable_error','updated_at'
  ] LOOP
    IF NOT has_column_privilege(
      '$policy_admin_application_role', 'public.policy_authority_executions',
      column_name, 'UPDATE'
    ) THEN RAISE EXCEPTION 'MIGRATION_POLICY_ADMIN_EXECUTION_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  IF EXISTS (
    SELECT 1 FROM information_schema.column_privileges AS column_grant
     WHERE column_grant.table_schema='public'
       AND column_grant.grantee='$policy_admin_application_role'
       AND column_grant.privilege_type='UPDATE'
       AND NOT (
         (column_grant.table_name='policy_sources'
          AND column_grant.column_name IN ('lifecycle_state','updated_at')) OR
         (column_grant.table_name='policy_bundles'
          AND column_grant.column_name IN ('status','deprecated_at')) OR
         (column_grant.table_name='policy_exceptions'
          AND column_grant.column_name IN (
           'revoked_at','revocation_reason_digest','expired_at'
         )) OR
         (column_grant.table_name='policy_promotions'
          AND column_grant.column_name IN ('state','completed_at')) OR
         (column_grant.table_name='policy_activation_intents'
          AND column_grant.column_name IN (
           'state','claim_owner','claim_expires_at','acknowledgement_digest',
           'acknowledgement','updated_at','activated_at'
         )) OR
         (column_grant.table_name='policy_resource_versions'
          AND column_grant.column_name IN (
           'resource_version','action_hash','ledger_execution_id','fence_digest','updated_at'
         )) OR
         (column_grant.table_name='policy_action_ingress'
          AND column_grant.column_name IN ('state','receipt','updated_at')) OR
         (column_grant.table_name='policy_authority_executions'
          AND column_grant.column_name IN (
           'state','safe_result','safe_result_digest','stable_error','updated_at'
         ))
       )
  ) THEN
    RAISE EXCEPTION 'MIGRATION_POLICY_ADMIN_EXCESS_COLUMN_UPDATE_GRANT';
  END IF;
  FOREACH table_name IN ARRAY incident_release_tables LOOP
    IF to_regclass(format('public.%I', table_name)) IS NULL THEN
      RAISE EXCEPTION 'MIGRATION_INCIDENT_RELEASE_TABLE_MISSING:%', table_name;
    END IF;
    IF table_name IN ('incident_evidence_events', 'incident_evidence_outbox') THEN
      IF NOT has_table_privilege(
        '$incident_release_application_role', format('public.%I', table_name), 'INSERT'
      ) OR has_table_privilege(
        '$incident_release_application_role', format('public.%I', table_name),
        'SELECT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
      ) THEN
        RAISE EXCEPTION 'MIGRATION_INCIDENT_RELEASE_EVIDENCE_GRANTS_INVALID:%', table_name;
      END IF;
    ELSIF NOT has_table_privilege(
      '$incident_release_application_role', format('public.%I', table_name), 'SELECT'
    ) OR NOT has_table_privilege(
      '$incident_release_application_role', format('public.%I', table_name), 'INSERT'
    ) OR has_table_privilege(
      '$incident_release_application_role', format('public.%I', table_name),
      'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
    ) THEN
      RAISE EXCEPTION 'MIGRATION_INCIDENT_RELEASE_GRANTS_INVALID:%', table_name;
    END IF;
  END LOOP;
  IF has_table_privilege(
       '$incident_release_application_role', 'public.release_gate_results',
       'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
     ) THEN
    RAISE EXCEPTION 'MIGRATION_INCIDENT_RELEASE_LEGACY_GATE_GRANT';
  END IF;
  FOREACH column_name IN ARRAY ARRAY[
    'status','owner','severity','resource_version','updated_at'
  ] LOOP
    IF NOT has_column_privilege(
      '$incident_release_application_role', 'public.incidents', column_name, 'UPDATE'
    ) THEN RAISE EXCEPTION 'MIGRATION_INCIDENT_RELEASE_INCIDENT_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY['state','receipt','updated_at'] LOOP
    IF NOT has_column_privilege(
      '$incident_release_application_role', 'public.incident_action_ingress',
      column_name, 'UPDATE'
    ) THEN RAISE EXCEPTION 'MIGRATION_INCIDENT_RELEASE_INGRESS_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY[
    'resource_version','action_hash','ledger_execution_id','fence_digest','updated_at'
  ] LOOP
    IF NOT has_column_privilege(
      '$incident_release_application_role', 'public.incident_resource_versions',
      column_name, 'UPDATE'
    ) THEN RAISE EXCEPTION 'MIGRATION_INCIDENT_RELEASE_VERSION_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY[
    'state','execution_owner','execution_lease_until','safe_result',
    'safe_result_digest','stable_error','updated_at'
  ] LOOP
    IF NOT has_column_privilege(
      '$incident_release_application_role', 'public.incident_authority_executions',
      column_name, 'UPDATE'
    ) THEN RAISE EXCEPTION 'MIGRATION_INCIDENT_RELEASE_EXECUTION_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY['state','updated_at'] LOOP
    IF NOT has_column_privilege(
      '$incident_release_application_role', 'public.release_gate_runs', column_name, 'UPDATE'
    ) THEN RAISE EXCEPTION 'MIGRATION_INCIDENT_RELEASE_GATE_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  IF EXISTS (
    SELECT 1 FROM information_schema.column_privileges AS column_grant
     WHERE column_grant.table_schema='public'
       AND column_grant.grantee='$incident_release_application_role'
       AND column_grant.privilege_type='UPDATE'
       AND NOT (
         (column_grant.table_name='incidents' AND column_grant.column_name IN (
           'status','owner','severity','resource_version','updated_at'
         )) OR
         (column_grant.table_name='incident_action_ingress'
          AND column_grant.column_name IN (
           'state','receipt','updated_at'
         )) OR
         (column_grant.table_name='incident_resource_versions'
          AND column_grant.column_name IN (
           'resource_version','action_hash','ledger_execution_id','fence_digest','updated_at'
         )) OR
         (column_grant.table_name='incident_authority_executions'
          AND column_grant.column_name IN (
           'state','execution_owner','execution_lease_until','safe_result',
           'safe_result_digest','stable_error','updated_at'
         )) OR
         (column_grant.table_name='release_gate_runs'
          AND column_grant.column_name IN ('state','updated_at'))
       )
  ) THEN
    RAISE EXCEPTION 'MIGRATION_INCIDENT_RELEASE_EXCESS_COLUMN_UPDATE_GRANT';
  END IF;
  FOREACH table_name IN ARRAY pack_marketplace_tables LOOP
    IF to_regclass(format('public.%I', table_name)) IS NULL THEN
      RAISE EXCEPTION 'MIGRATION_PACK_MARKETPLACE_TABLE_MISSING:%', table_name;
    END IF;
    IF table_name IN ('marketplace_evidence_events', 'marketplace_evidence_outbox') THEN
      IF NOT has_table_privilege(
        '$pack_marketplace_application_role', format('public.%I', table_name), 'INSERT'
      ) OR has_table_privilege(
        '$pack_marketplace_application_role', format('public.%I', table_name),
        'SELECT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
      ) THEN
        RAISE EXCEPTION 'MIGRATION_PACK_MARKETPLACE_EVIDENCE_GRANTS_INVALID:%', table_name;
      END IF;
    ELSIF NOT has_table_privilege(
      '$pack_marketplace_application_role', format('public.%I', table_name), 'SELECT'
    ) OR NOT has_table_privilege(
      '$pack_marketplace_application_role', format('public.%I', table_name), 'INSERT'
    ) OR has_table_privilege(
      '$pack_marketplace_application_role', format('public.%I', table_name),
      'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
    ) THEN
      RAISE EXCEPTION 'MIGRATION_PACK_MARKETPLACE_GRANTS_INVALID:%', table_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY[
    'trust_status','verified_by','verified_at','revoked_at','updated_at'
  ] LOOP
    IF NOT has_column_privilege(
      '$pack_marketplace_application_role', 'public.marketplace_publishers',
      column_name, 'UPDATE'
    ) THEN RAISE EXCEPTION 'MIGRATION_PACK_MARKETPLACE_PUBLISHER_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY['status','revoked_at'] LOOP
    IF NOT has_column_privilege(
      '$pack_marketplace_application_role', 'public.marketplace_publisher_keys',
      column_name, 'UPDATE'
    ) THEN RAISE EXCEPTION 'MIGRATION_PACK_MARKETPLACE_KEY_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY[
    'control_plane_version','region','entitlements','allowed_compatibility',
    'minimum_publisher_trust','maximum_risk','configured_by','updated_at'
  ] LOOP
    IF NOT has_column_privilege(
      '$pack_marketplace_application_role', 'public.marketplace_tenant_catalog',
      column_name, 'UPDATE'
    ) THEN RAISE EXCEPTION 'MIGRATION_PACK_MARKETPLACE_CATALOG_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY[
    'review_status','reviewed_by','review_digest','published_at','revoked_at','updated_at'
  ] LOOP
    IF NOT has_column_privilege(
      '$pack_marketplace_application_role', 'public.marketplace_releases',
      column_name, 'UPDATE'
    ) THEN RAISE EXCEPTION 'MIGRATION_PACK_MARKETPLACE_RELEASE_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY[
    'state','approved_by','approval_digest','artifact_receipt_digest',
    'previous_installation_id','production_certificate_digest',
    'deactivation_reason_digest','approved_at','installed_at','activated_at',
    'deactivated_at','revoked_at','updated_at'
  ] LOOP
    IF NOT has_column_privilege(
      '$pack_marketplace_application_role', 'public.marketplace_installations',
      column_name, 'UPDATE'
    ) THEN RAISE EXCEPTION 'MIGRATION_PACK_MARKETPLACE_INSTALLATION_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY[
    'state','rollback_reason_digest','completed_at','rolled_back_at','updated_at'
  ] LOOP
    IF NOT has_column_privilege(
      '$pack_marketplace_application_role', 'public.marketplace_upgrade_plans',
      column_name, 'UPDATE'
    ) THEN RAISE EXCEPTION 'MIGRATION_PACK_MARKETPLACE_UPGRADE_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY[
    'resource_version','action_hash','policy_decision_id','ledger_entry_id',
    'ledger_execution_id','fence_digest','updated_at'
  ] LOOP
    IF NOT has_column_privilege(
      '$pack_marketplace_application_role', 'public.marketplace_resource_versions',
      column_name, 'UPDATE'
    ) THEN RAISE EXCEPTION 'MIGRATION_PACK_MARKETPLACE_VERSION_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY['state','receipt','updated_at'] LOOP
    IF NOT has_column_privilege(
      '$pack_marketplace_application_role', 'public.marketplace_action_ingress',
      column_name, 'UPDATE'
    ) THEN RAISE EXCEPTION 'MIGRATION_PACK_MARKETPLACE_INGRESS_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  FOREACH column_name IN ARRAY ARRAY[
    'state','safe_result','safe_result_digest','stable_error','updated_at'
  ] LOOP
    IF NOT has_column_privilege(
      '$pack_marketplace_application_role', 'public.marketplace_authority_executions',
      column_name, 'UPDATE'
    ) THEN RAISE EXCEPTION 'MIGRATION_PACK_MARKETPLACE_EXECUTION_UPDATE_MISSING:%', column_name;
    END IF;
  END LOOP;
  IF EXISTS (
    SELECT 1 FROM information_schema.column_privileges AS column_grant
     WHERE column_grant.table_schema='public'
       AND column_grant.grantee='$pack_marketplace_application_role'
       AND column_grant.privilege_type='UPDATE'
       AND NOT (
         (column_grant.table_name='marketplace_publishers'
          AND column_grant.column_name IN (
           'trust_status','verified_by','verified_at','revoked_at','updated_at'
         )) OR
         (column_grant.table_name='marketplace_publisher_keys'
          AND column_grant.column_name IN ('status','revoked_at')) OR
         (column_grant.table_name='marketplace_tenant_catalog'
          AND column_grant.column_name IN (
           'control_plane_version','region','entitlements','allowed_compatibility',
           'minimum_publisher_trust','maximum_risk','configured_by','updated_at'
         )) OR
         (column_grant.table_name='marketplace_releases'
          AND column_grant.column_name IN (
           'review_status','reviewed_by','review_digest','published_at','revoked_at','updated_at'
         )) OR
         (column_grant.table_name='marketplace_installations'
          AND column_grant.column_name IN (
           'state','approved_by','approval_digest','artifact_receipt_digest',
           'previous_installation_id','production_certificate_digest',
           'deactivation_reason_digest','approved_at','installed_at','activated_at',
           'deactivated_at','revoked_at','updated_at'
         )) OR
         (column_grant.table_name='marketplace_upgrade_plans'
          AND column_grant.column_name IN (
           'state','rollback_reason_digest','completed_at','rolled_back_at','updated_at'
         )) OR
         (column_grant.table_name='marketplace_resource_versions'
          AND column_grant.column_name IN (
           'resource_version','action_hash','policy_decision_id','ledger_entry_id',
           'ledger_execution_id','fence_digest','updated_at'
         )) OR
         (column_grant.table_name='marketplace_action_ingress'
          AND column_grant.column_name IN (
           'state','receipt','updated_at'
         )) OR
         (column_grant.table_name='marketplace_authority_executions'
          AND column_grant.column_name IN (
           'state','safe_result','safe_result_digest','stable_error','updated_at'
         ))
       )
  ) THEN
    RAISE EXCEPTION 'MIGRATION_PACK_MARKETPLACE_EXCESS_COLUMN_UPDATE_GRANT';
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
     OR has_schema_privilege('$enterprise_authority_application_role', 'public', 'CREATE')
     OR has_schema_privilege('$orchestrator_application_role', 'public', 'CREATE')
     OR has_schema_privilege('$execution_application_role', 'public', 'CREATE')
     OR has_schema_privilege('$registry_application_role', 'public', 'CREATE')
     OR has_schema_privilege('$agent_registry_application_role', 'public', 'CREATE')
     OR has_schema_privilege('$policy_admin_application_role', 'public', 'CREATE')
     OR has_schema_privilege('$incident_release_application_role', 'public', 'CREATE')
     OR has_schema_privilege('$pack_marketplace_application_role', 'public', 'CREATE')
     OR has_schema_privilege('$approval_application_role', 'public', 'CREATE')
     OR has_schema_privilege('$pep_application_role', 'public', 'CREATE')
     OR has_schema_privilege('$identity_application_role', 'public', 'CREATE')
     OR has_schema_privilege('$tool_proxy_application_role', 'public', 'CREATE')
     OR has_schema_privilege('$evidence_application_role', 'public', 'CREATE')
     OR has_schema_privilege('$audit_application_role', 'public', 'CREATE')
     OR NOT has_schema_privilege('$enterprise_application_role', 'public', 'USAGE')
     OR NOT has_schema_privilege('$enterprise_authority_application_role', 'public', 'USAGE')
     OR NOT has_schema_privilege('$orchestrator_application_role', 'public', 'USAGE')
     OR NOT has_schema_privilege('$execution_application_role', 'public', 'USAGE')
     OR NOT has_schema_privilege('$registry_application_role', 'public', 'USAGE')
     OR NOT has_schema_privilege('$agent_registry_application_role', 'public', 'USAGE')
     OR NOT has_schema_privilege('$policy_admin_application_role', 'public', 'USAGE')
     OR NOT has_schema_privilege('$incident_release_application_role', 'public', 'USAGE')
     OR NOT has_schema_privilege('$pack_marketplace_application_role', 'public', 'USAGE')
     OR NOT has_schema_privilege('$approval_application_role', 'public', 'USAGE')
     OR NOT has_schema_privilege('$pep_application_role', 'public', 'USAGE')
     OR NOT has_schema_privilege('$identity_application_role', 'public', 'USAGE')
     OR NOT has_schema_privilege('$tool_proxy_application_role', 'public', 'USAGE')
     OR NOT has_schema_privilege('$evidence_application_role', 'public', 'USAGE')
     OR NOT has_schema_privilege('$audit_application_role', 'public', 'USAGE')
     OR NOT has_database_privilege(
       '$enterprise_application_role', current_database(), 'CONNECT'
     )
     OR NOT has_database_privilege(
       '$enterprise_authority_application_role', current_database(), 'CONNECT'
     )
     OR NOT has_database_privilege(
       '$orchestrator_application_role', current_database(), 'CONNECT'
     )
     OR NOT has_database_privilege(
       '$execution_application_role', current_database(), 'CONNECT'
     )
     OR NOT has_database_privilege(
       '$registry_application_role', current_database(), 'CONNECT'
     )
     OR NOT has_database_privilege(
       '$agent_registry_application_role', current_database(), 'CONNECT'
     )
     OR NOT has_database_privilege(
       '$policy_admin_application_role', current_database(), 'CONNECT'
     )
     OR NOT has_database_privilege(
       '$incident_release_application_role', current_database(), 'CONNECT'
     )
     OR NOT has_database_privilege(
       '$pack_marketplace_application_role', current_database(), 'CONNECT'
     )
     OR NOT has_database_privilege(
       '$approval_application_role', current_database(), 'CONNECT'
     )
     OR NOT has_database_privilege(
       '$pep_application_role', current_database(), 'CONNECT'
     )
     OR NOT has_database_privilege(
       '$identity_application_role', current_database(), 'CONNECT'
     )
     OR NOT has_database_privilege(
       '$tool_proxy_application_role', current_database(), 'CONNECT'
     )
     OR NOT has_database_privilege(
       '$evidence_application_role', current_database(), 'CONNECT'
     )
     OR NOT has_database_privilege(
       '$audit_application_role', current_database(), 'CONNECT'
     )
     OR has_database_privilege(
       '$enterprise_application_role', current_database(), 'TEMP'
     )
     OR has_database_privilege(
       '$enterprise_authority_application_role', current_database(), 'TEMP'
     )
     OR has_database_privilege(
       '$orchestrator_application_role', current_database(), 'TEMP'
     )
     OR has_database_privilege(
       '$execution_application_role', current_database(), 'TEMP'
     )
     OR has_database_privilege(
       '$registry_application_role', current_database(), 'TEMP'
     )
     OR has_database_privilege(
       '$agent_registry_application_role', current_database(), 'TEMP'
     )
     OR has_database_privilege(
       '$policy_admin_application_role', current_database(), 'TEMP'
     )
     OR has_database_privilege(
       '$incident_release_application_role', current_database(), 'TEMP'
     )
     OR has_database_privilege(
       '$pack_marketplace_application_role', current_database(), 'TEMP'
     )
     OR has_database_privilege(
       '$approval_application_role', current_database(), 'TEMP'
     )
     OR has_database_privilege(
       '$pep_application_role', current_database(), 'TEMP'
     )
     OR has_database_privilege(
       '$identity_application_role', current_database(), 'TEMP'
     )
     OR has_database_privilege(
       '$tool_proxy_application_role', current_database(), 'TEMP'
     )
     OR has_database_privilege(
       '$evidence_application_role', current_database(), 'TEMP'
     )
     OR has_database_privilege(
       '$audit_application_role', current_database(), 'TEMP'
     ) THEN
    RAISE EXCEPTION 'MIGRATION_APPLICATION_SCHEMA_GRANTS_INVALID';
  END IF;
  IF has_table_privilege(
       '$enterprise_application_role', 'public.agenttrust_schema_migrations',
       'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
     )
     OR has_table_privilege(
       '$enterprise_authority_application_role', 'public.agenttrust_schema_migrations',
       'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
     )
     OR has_table_privilege(
       '$orchestrator_application_role', 'public.agenttrust_schema_migrations',
       'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
     )
     OR has_table_privilege(
       '$execution_application_role', 'public.agenttrust_schema_migrations',
       'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
     )
     OR has_table_privilege(
       '$registry_application_role', 'public.agenttrust_schema_migrations',
       'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
     )
     OR has_table_privilege(
       '$agent_registry_application_role', 'public.agenttrust_schema_migrations',
       'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
     )
     OR has_table_privilege(
       '$policy_admin_application_role', 'public.agenttrust_schema_migrations',
       'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
     )
     OR has_table_privilege(
       '$incident_release_application_role', 'public.agenttrust_schema_migrations',
       'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
     )
     OR has_table_privilege(
       '$pack_marketplace_application_role', 'public.agenttrust_schema_migrations',
       'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
     )
     OR has_table_privilege(
       '$approval_application_role', 'public.agenttrust_schema_migrations',
       'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
     )
     OR has_table_privilege(
       '$pep_application_role', 'public.agenttrust_schema_migrations',
       'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
     )
     OR has_table_privilege(
       '$identity_application_role', 'public.agenttrust_schema_migrations',
       'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
     )
     OR has_table_privilege(
       '$tool_proxy_application_role', 'public.agenttrust_schema_migrations',
       'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
     )
     OR has_table_privilege(
       '$evidence_application_role', 'public.agenttrust_schema_migrations',
       'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
     )
     OR has_table_privilege(
       '$audit_application_role', 'public.agenttrust_schema_migrations',
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
       AND relation.relname <> ALL (enterprise_authority_tables)
       AND has_table_privilege(
         '$enterprise_authority_application_role', relation.oid,
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
  ) OR EXISTS (
    SELECT 1
      FROM pg_class AS relation
      JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = 'public'
       AND relation.relkind IN ('r', 'p')
       AND relation.relname <> ALL (registry_tables)
       AND has_table_privilege(
         '$registry_application_role', relation.oid,
         'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
       )
  ) OR EXISTS (
    SELECT 1
      FROM pg_class AS relation
      JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = 'public'
       AND relation.relkind IN ('r', 'p')
       AND relation.relname <> ALL (agent_registry_tables)
       AND has_table_privilege(
         '$agent_registry_application_role', relation.oid,
         'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
       )
  ) OR EXISTS (
    SELECT 1
      FROM pg_class AS relation
      JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = 'public'
       AND relation.relkind IN ('r', 'p')
       AND relation.relname <> ALL (policy_admin_tables)
       AND has_table_privilege(
         '$policy_admin_application_role', relation.oid,
         'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
       )
  ) OR EXISTS (
    SELECT 1
      FROM pg_class AS relation
      JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = 'public'
       AND relation.relkind IN ('r', 'p')
       AND relation.relname <> ALL (incident_release_tables)
       AND has_table_privilege(
         '$incident_release_application_role', relation.oid,
         'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
       )
  ) OR EXISTS (
    SELECT 1
      FROM pg_class AS relation
      JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = 'public'
       AND relation.relkind IN ('r', 'p')
       AND relation.relname <> ALL (pack_marketplace_tables)
       AND has_table_privilege(
         '$pack_marketplace_application_role', relation.oid,
         'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
       )
  ) OR EXISTS (
    SELECT 1
      FROM pg_class AS relation
      JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = 'public'
       AND relation.relkind IN ('r', 'p')
       AND relation.relname <> ALL (approval_tables)
       AND has_table_privilege(
         '$approval_application_role', relation.oid,
         'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
       )
  ) OR EXISTS (
    SELECT 1
      FROM pg_class AS relation
      JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = 'public'
       AND relation.relkind IN ('r', 'p')
       AND relation.relname <> ALL (pep_tables)
       AND has_table_privilege(
         '$pep_application_role', relation.oid,
         'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
       )
  ) OR EXISTS (
    SELECT 1
      FROM pg_class AS relation
      JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = 'public'
       AND relation.relkind IN ('r', 'p')
       AND relation.relname <> ALL (identity_tables)
       AND has_table_privilege(
         '$identity_application_role', relation.oid,
         'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
       )
  ) OR EXISTS (
    SELECT 1
      FROM pg_class AS relation
      JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = 'public'
       AND relation.relkind IN ('r', 'p')
       AND relation.relname <> ALL (tool_proxy_tables)
       AND has_table_privilege(
         '$tool_proxy_application_role', relation.oid,
         'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
       )
  ) OR EXISTS (
    SELECT 1
      FROM pg_class AS relation
      JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = 'public'
       AND relation.relkind IN ('r', 'p')
       AND relation.relname <> ALL (evidence_tables)
       AND has_table_privilege(
         '$evidence_application_role', relation.oid,
         'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
       )
  ) OR EXISTS (
    SELECT 1
      FROM pg_class AS relation
      JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = 'public'
       AND relation.relkind IN ('r', 'p')
       AND relation.relname <> ALL (audit_tables)
       AND has_table_privilege(
         '$audit_application_role', relation.oid,
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
           '$enterprise_authority_application_role', relation.oid,
           'TRUNCATE,REFERENCES,TRIGGER'
         )
         OR has_table_privilege(
           '$orchestrator_application_role', relation.oid, 'TRUNCATE,REFERENCES,TRIGGER'
         )
         OR has_table_privilege(
           '$execution_application_role', relation.oid, 'TRUNCATE,REFERENCES,TRIGGER'
         )
         OR has_table_privilege(
           '$registry_application_role', relation.oid, 'TRUNCATE,REFERENCES,TRIGGER'
         )
         OR has_table_privilege(
           '$agent_registry_application_role', relation.oid, 'TRUNCATE,REFERENCES,TRIGGER'
         )
         OR has_table_privilege(
           '$policy_admin_application_role', relation.oid, 'TRUNCATE,REFERENCES,TRIGGER'
         )
         OR has_table_privilege(
           '$incident_release_application_role', relation.oid,
           'TRUNCATE,REFERENCES,TRIGGER'
         )
         OR has_table_privilege(
           '$pack_marketplace_application_role', relation.oid,
           'TRUNCATE,REFERENCES,TRIGGER'
         )
         OR has_table_privilege(
           '$approval_application_role', relation.oid, 'TRUNCATE,REFERENCES,TRIGGER'
         )
         OR has_table_privilege(
           '$pep_application_role', relation.oid, 'TRUNCATE,REFERENCES,TRIGGER'
         )
         OR has_table_privilege(
           '$identity_application_role', relation.oid, 'TRUNCATE,REFERENCES,TRIGGER'
         )
         OR has_table_privilege(
           '$tool_proxy_application_role', relation.oid, 'TRUNCATE,REFERENCES,TRIGGER'
         )
         OR has_table_privilege(
           '$evidence_application_role', relation.oid, 'TRUNCATE,REFERENCES,TRIGGER'
         )
         OR has_table_privilege(
           '$audit_application_role', relation.oid, 'TRUNCATE,REFERENCES,TRIGGER'
         )
       )
  ) THEN
    RAISE EXCEPTION 'MIGRATION_APPLICATION_ROLE_EXCESS_TABLE_GRANT';
  END IF;
  IF EXISTS (
    WITH public_sequences AS MATERIALIZED (
      SELECT catalog_sequence.oid, catalog_sequence.relname
        FROM pg_catalog.pg_class AS catalog_sequence
        JOIN pg_catalog.pg_namespace AS catalog_namespace
          ON catalog_namespace.oid = catalog_sequence.relnamespace
       WHERE catalog_namespace.nspname = 'public'
         AND catalog_sequence.relkind = 'S'
    )
    SELECT 1
      FROM public_sequences AS public_sequence
     WHERE has_sequence_privilege(
       '$enterprise_application_role', public_sequence.oid, 'USAGE,SELECT,UPDATE'
     )
        OR has_sequence_privilege(
          '$enterprise_authority_application_role',
          public_sequence.oid,
          'USAGE,SELECT,UPDATE'
        )
        OR (
          (
            public_sequence.relname <> 'orchestrator_stream_events_sequence_seq'
            OR has_sequence_privilege(
              '$orchestrator_application_role', public_sequence.oid, 'SELECT,UPDATE'
            )
          )
          AND has_sequence_privilege(
            '$orchestrator_application_role',
            public_sequence.oid,
            'USAGE,SELECT,UPDATE'
          )
        )
        OR has_sequence_privilege(
          '$agent_registry_application_role', public_sequence.oid, 'USAGE,SELECT,UPDATE'
        )
        OR has_sequence_privilege(
          '$policy_admin_application_role', public_sequence.oid, 'USAGE,SELECT,UPDATE'
        )
        OR has_sequence_privilege(
          '$incident_release_application_role', public_sequence.oid, 'USAGE,SELECT,UPDATE'
        )
        OR has_sequence_privilege(
          '$pack_marketplace_application_role', public_sequence.oid, 'USAGE,SELECT,UPDATE'
        )
        OR (
          (
            public_sequence.relname <> 'execution_fence_seq'
            OR has_sequence_privilege(
              '$execution_application_role', public_sequence.oid, 'SELECT,UPDATE'
            )
          )
          AND has_sequence_privilege(
            '$execution_application_role', public_sequence.oid, 'USAGE,SELECT,UPDATE'
          )
        )
        OR has_sequence_privilege(
          '$registry_application_role', public_sequence.oid, 'USAGE,SELECT,UPDATE'
        )
        OR has_sequence_privilege(
          '$approval_application_role', public_sequence.oid, 'USAGE,SELECT,UPDATE'
        )
        OR has_sequence_privilege(
          '$pep_application_role', public_sequence.oid, 'USAGE,SELECT,UPDATE'
        )
        OR has_sequence_privilege(
          '$identity_application_role', public_sequence.oid, 'USAGE,SELECT,UPDATE'
        )
        OR has_sequence_privilege(
          '$tool_proxy_application_role', public_sequence.oid, 'USAGE,SELECT,UPDATE'
        )
        OR has_sequence_privilege(
          '$evidence_application_role', public_sequence.oid, 'USAGE,SELECT,UPDATE'
        )
        OR has_sequence_privilege(
          '$audit_application_role', public_sequence.oid, 'USAGE,SELECT,UPDATE'
        )
  ) THEN
    RAISE EXCEPTION 'MIGRATION_APPLICATION_ROLE_EXCESS_SEQUENCE_GRANT';
  END IF;
  IF EXISTS (
    SELECT 1
      FROM pg_proc AS function
      JOIN pg_namespace AS namespace ON namespace.oid = function.pronamespace
     WHERE namespace.nspname = 'public'
       AND (
         has_function_privilege('$enterprise_application_role', function.oid, 'EXECUTE')
         OR has_function_privilege(
           '$enterprise_authority_application_role', function.oid, 'EXECUTE'
         )
         OR has_function_privilege('$orchestrator_application_role', function.oid, 'EXECUTE')
         OR has_function_privilege('$execution_application_role', function.oid, 'EXECUTE')
         OR has_function_privilege('$registry_application_role', function.oid, 'EXECUTE')
         OR has_function_privilege('$agent_registry_application_role', function.oid, 'EXECUTE')
         OR has_function_privilege('$policy_admin_application_role', function.oid, 'EXECUTE')
         OR has_function_privilege('$incident_release_application_role', function.oid, 'EXECUTE')
         OR has_function_privilege('$pack_marketplace_application_role', function.oid, 'EXECUTE')
         OR has_function_privilege('$approval_application_role', function.oid, 'EXECUTE')
         OR has_function_privilege('$pep_application_role', function.oid, 'EXECUTE')
         OR has_function_privilege('$identity_application_role', function.oid, 'EXECUTE')
         OR has_function_privilege('$tool_proxy_application_role', function.oid, 'EXECUTE')
         OR has_function_privilege('$evidence_application_role', function.oid, 'EXECUTE')
         OR has_function_privilege('$audit_application_role', function.oid, 'EXECUTE')
       )
  ) THEN
    RAISE EXCEPTION 'MIGRATION_APPLICATION_ROLE_EXCESS_FUNCTION_GRANT';
  END IF;
END
\$application_grants\$;
DO \$production_authority_posture\$
DECLARE role_name text;
BEGIN
  FOREACH role_name IN ARRAY ARRAY[
    '$model_gateway_application_role', '$data_governance_application_role',
    '$context_governance_application_role', '$runtime_anomaly_application_role',
    '$security_evaluation_application_role', '$pack_supply_chain_application_role',
    '$domain_runtime_application_role', '$platform_sre_application_role'
  ] LOOP
    IF NOT has_database_privilege(role_name,current_database(),'CONNECT')
       OR has_database_privilege(role_name,current_database(),'TEMP')
       OR NOT has_schema_privilege(role_name,'public','USAGE')
       OR has_schema_privilege(role_name,'public','CREATE')
       OR has_table_privilege(role_name,'public.agenttrust_schema_migrations','SELECT,INSERT,UPDATE,DELETE')
       OR NOT EXISTS (SELECT 1 FROM information_schema.role_table_grants
                       WHERE grantee=role_name AND table_schema='public')
       OR EXISTS (SELECT 1 FROM information_schema.role_table_grants
                   WHERE grantee=role_name AND table_schema='public'
                     AND privilege_type IN ('DELETE','TRUNCATE','REFERENCES','TRIGGER'))
       OR EXISTS (SELECT 1 FROM information_schema.role_routine_grants
                   WHERE grantee=role_name AND routine_schema='public')
       OR EXISTS (SELECT 1 FROM information_schema.role_usage_grants
                   WHERE grantee=role_name AND object_type='SEQUENCE') THEN
      RAISE EXCEPTION 'MIGRATION_PRODUCTION_AUTHORITY_ROLE_POSTURE_INVALID:%', role_name;
    END IF;
  END LOOP;
END
\$production_authority_posture\$;
SQL
if [ "$mode" = "--apply" ]; then
  printf '%s\n' 'COMMIT;' >>"$sql_file"
fi
cat >>"$sql_file" <<'SQL'
SELECT pg_advisory_unlock(hashtextextended('agenttrust-production-migrations', 0));
SQL

database_connect_timeout="${AGENT_TRUST_DATABASE_CONNECT_TIMEOUT_SECONDS:-10}"
case "$database_connect_timeout" in
  ''|*[!0-9]*) echo "MIGRATION_DATABASE_CONNECT_TIMEOUT_INVALID" >&2; exit 78 ;;
esac
if [ "${#database_connect_timeout}" -gt 2 ] \
  || [ "$database_connect_timeout" -lt 1 ] || [ "$database_connect_timeout" -gt 60 ]; then
  echo "MIGRATION_DATABASE_CONNECT_TIMEOUT_INVALID" >&2
  exit 78
fi
# PostgreSQL 13 introduced libpq's channel_binding control. Older clients can
# silently ignore an unknown environment variable, so reject them before a
# connection is attempted. The SQL transport assertion below independently
# proves the negotiated TLS version rather than trusting client configuration.
if ! psql_version_output=$(LC_ALL=C psql --version 2>/dev/null); then
  echo "MIGRATION_PSQL_CLIENT_UNSUPPORTED" >&2
  exit 78
fi
case "$psql_version_output" in
  *'
'*) echo "MIGRATION_PSQL_CLIENT_UNSUPPORTED" >&2; exit 78 ;;
  "psql (PostgreSQL) "*) ;;
  *) echo "MIGRATION_PSQL_CLIENT_UNSUPPORTED" >&2; exit 78 ;;
esac
psql_version_prefix='psql (PostgreSQL) '
psql_version=${psql_version_output#"$psql_version_prefix"}
psql_version=${psql_version%% *}
psql_major=${psql_version%%.*}
case "$psql_major" in
  ''|*[!0-9]*) echo "MIGRATION_PSQL_CLIENT_UNSUPPORTED" >&2; exit 78 ;;
esac
if [ "${#psql_major}" -gt 3 ] || [ "$psql_major" -lt 13 ]; then
  echo "MIGRATION_PSQL_CLIENT_UNSUPPORTED" >&2
  exit 78
fi
unset psql_version_output psql_version_prefix psql_version psql_major
# Eliminate inherited libpq routing/authentication overrides before setting the
# exact production connection contract below.
unset PGHOSTADDR PGSERVICE PGSERVICEFILE PGOPTIONS PGTARGETSESSIONATTRS
unset PGLOADBALANCEHOSTS PGREQUIREPEER PGKRBSRVNAME PGGSSLIB
unset PGSSLCRL PGSSLCRLDIR PGSSLCERT PGSSLKEY PGSSLCERTMODE PGSSLSNI
unset PGSSLMAXPROTOCOLVERSION PGREQUIRESSL PGREQUIREAUTH
unset PGOAUTHCLIENTID PGOAUTHCLIENTSECRET PGOAUTHISSUER
export PGCONNECT_TIMEOUT="$database_connect_timeout"
export PGAPPNAME="agenttrust-production-migrations"
export PGHOST="$database_host"
export PGPORT="$database_port"
export PGUSER="$database_user"
export PGDATABASE="$database_name"
export PGSSLMODE=verify-full
export PGSSLROOTCERT="$database_ca_file"
export PGSSLMINPROTOCOLVERSION=TLSv1.3
export PGCHANNELBINDING=require
export PGGSSENCMODE=disable
export PGCLIENTENCODING=UTF8
export PGPASSFILE="$pgpass_file"
# Connection metadata is split across libpq variables and the password is held
# only in the 0600 temporary passfile; neither secret nor URI enters argv.
psql --no-psqlrc --file "$sql_file" &
psql_pid=$!
if wait "$psql_pid"; then
  psql_status=0
else
  psql_status=$?
fi
psql_pid=
exit "$psql_status"
