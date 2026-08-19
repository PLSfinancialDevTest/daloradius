#!/usr/bin/env bash
set -euo pipefail

GROUP_NAME="${1:-PLS-Store-Radius}"
DB_NAME="radius"
COMPANY="PLS Financial Services"
DEPARTMENT="Infrastructure"
CREATED_BY="apache-kerberos-sso-sync"
DUMMY_PASSWORD="KERBEROS_SSO_ONLY_DO_NOT_USE_LOCAL_PASSWORD"

echo "[INFO] Syncing daloRADIUS operators from AD group: ${GROUP_NAME}"

GROUP_LINE="$(getent group "${GROUP_NAME}" || true)"

if [[ -z "${GROUP_LINE}" ]]; then
    echo "[ERROR] Group not found through NSS/SSSD: ${GROUP_NAME}"
    echo "[INFO] Try: getent group \"pls-store-radius\""
    exit 1
fi

MEMBERS_RAW="$(echo "${GROUP_LINE}" | awk -F: '{print $4}')"

if [[ -z "${MEMBERS_RAW}" ]]; then
    echo "[WARN] Group was found but no direct members were returned by getent."
    echo "[WARN] If this AD group uses nested groups, SSSD may not enumerate nested members through getent."
    exit 0
fi

echo "${MEMBERS_RAW}" | tr ',' '\n' | while read -r raw_user; do
    raw_user="$(echo "${raw_user}" | xargs)"

    [[ -z "${raw_user}" ]] && continue

    user="$(echo "${raw_user}" | tr '[:upper:]' '[:lower:]')"
    user="${user%@*}"
    user="${user#plsfinancial\\}"

    if [[ ${#user} -gt 32 ]]; then
        echo "[WARN] Skipping '${user}' because username length exceeds 32 characters."
        continue
    fi

    if ! [[ "${user}" =~ ^[a-z0-9._-]+$ ]]; then
        echo "[WARN] Skipping '${user}' because it contains unexpected characters."
        continue
    fi

    email="${user}@plsfinancial.com"

    echo "[INFO] Ensuring daloRADIUS admin operator exists: ${user}"

    mysql "${DB_NAME}" <<SQL
SET @op_user := '${user}';
SET @op_id := NULL;

SELECT id INTO @op_id FROM operators WHERE username = @op_user ORDER BY id LIMIT 1;

INSERT INTO operators (
    username,
    password,
    firstname,
    lastname,
    title,
    department,
    company,
    phone1,
    phone2,
    email1,
    email2,
    messenger1,
    messenger2,
    notes,
    lastlogin,
    creationdate,
    creationby,
    updatedate,
    updateby,
    totp_enabled,
    totp_secret,
    totp_last_counter,
    totp_confirmed_at,
    totp_recovery_codes
)
SELECT
    @op_user,
    '${DUMMY_PASSWORD}',
    @op_user,
    '',
    'daloRADIUS Administrator',
    '${DEPARTMENT}',
    '${COMPANY}',
    '',
    '',
    '${email}',
    '',
    '',
    '',
    'Auto-synced from AD group ${GROUP_NAME}. Access controlled by Apache Kerberos and AD group membership.',
    NULL,
    NOW(),
    '${CREATED_BY}',
    NOW(),
    '${CREATED_BY}',
    0,
    NULL,
    NULL,
    NULL,
    NULL
WHERE @op_id IS NULL;

SET @op_id := NULL;
SELECT id INTO @op_id FROM operators WHERE username = @op_user ORDER BY id LIMIT 1;

INSERT INTO operators_acl (
    operator_id,
    file,
    access
)
SELECT
    @op_id,
    f.file,
    1
FROM operators_acl_files f
WHERE NOT EXISTS (
    SELECT 1
    FROM operators_acl a
    WHERE a.operator_id = @op_id
      AND a.file = f.file
);

UPDATE operators_acl SET access = 1 WHERE operator_id = @op_id;
SQL
done

echo "[INFO] Sync complete."
