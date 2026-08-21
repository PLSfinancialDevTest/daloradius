#!/usr/bin/env bash
set -euo pipefail

QCONF="${1:-}"

if [[ -z "${QCONF}" ]]; then
    if [[ -f "/etc/freeradius/3.0/mods-config/sql/main/mysql/queries.conf" ]]; then
        QCONF="/etc/freeradius/3.0/mods-config/sql/main/mysql/queries.conf"
    else
        QCONF="$(find /etc/freeradius -type f -name queries.conf 2>/dev/null | head -n 1 || true)"
    fi
fi

if [[ -z "${QCONF}" || ! -f "${QCONF}" ]]; then
    echo "[ERROR] Could not find queries.conf."
    echo "[INFO] Usage: sudo $0 /path/to/queries.conf"
    exit 1
fi

if [[ ! -r "${QCONF}" || ! -w "${QCONF}" ]]; then
    echo "[ERROR] Need read/write access to ${QCONF}. Run with sudo."
    exit 1
fi

MODE=""
if grep -qE "^\s*postauth_query\s*=" "${QCONF}"; then
    MODE="legacy"
elif grep -qE "post-auth\s*\{" "${QCONF}"; then
    MODE="block"
else
    echo "[ERROR] Could not find either postauth_query= or post-auth { ... query = ... } in ${QCONF}."
    exit 1
fi

BACKUP="${QCONF}.bak.$(date +%F-%H%M%S)"
cp "${QCONF}" "${BACKUP}"
echo "[INFO] Backup created: ${BACKUP}"

if [[ "${MODE}" == "legacy" ]]; then
    OLD_BLOCK="$(perl -0777 -ne 'if(/postauth_query\s*=\s*"(.*?)"/s){print $1}' "${QCONF}")"
else
    OLD_BLOCK="$(perl -0777 -ne 'if(/post-auth\s*\{.*?\bquery\s*=\s*"(.*?)"/s){print $1}' "${QCONF}")"
fi

TS_FMT="%S"
if [[ "${OLD_BLOCK}" == *"%S.%M"* ]]; then
    TS_FMT="%S.%M"
elif [[ "${OLD_BLOCK}" == *"%L"* ]]; then
    TS_FMT="%L"
fi

echo "[INFO] Using authdate format token: ${TS_FMT}"

read -r -d '' LEGACY_REPLACEMENT <<EOF || true
postauth_query = "INSERT INTO __POSTAUTH_TABLE__ (username, pass, reply, authdate, nasipaddress, calledstationid, nasidentifier) VALUES ('%{SQL-User-Name}', '%{%{User-Password}:-%{Chap-Password}}', '%{reply:Packet-Type}', '${TS_FMT}', '%{%{NAS-IP-Address}:-}', '%{%{Called-Station-Id}:-}', '%{%{NAS-Identifier}:-}')"
EOF

read -r -d '' BLOCK_QUERY <<'EOF' || true
INSERT INTO __POSTAUTH_TABLE_DOT__ (username, pass, reply, authdate, nasipaddress, calledstationid, nasidentifier __CLASS_COL__) VALUES ('%{SQL-User-Name}', '%{%{User-Password}:-%{Chap-Password}}', '%{reply:Packet-Type}', '__TS_FMT__', '%{%{NAS-IP-Address}:-}', '%{%{Called-Station-Id}:-}', '%{%{NAS-Identifier}:-}' __CLASS_REPLY__)
EOF

BLOCK_QUERY="${BLOCK_QUERY/__TS_FMT__/${TS_FMT}}"
BLOCK_QUERY="${BLOCK_QUERY/__POSTAUTH_TABLE_DOT__/\$\{..postauth_table\}}"
BLOCK_QUERY="${BLOCK_QUERY/__CLASS_COL__/\$\{..class.column_name\}}"
BLOCK_QUERY="${BLOCK_QUERY/__CLASS_REPLY__/\$\{..class.reply_xlat\}}"

TMP_FILE="$(mktemp)"
if [[ "${MODE}" == "legacy" ]]; then
    perl -0777 -pe "s#^\\s*postauth_query\\s*=\\s*\".*?\"#${LEGACY_REPLACEMENT}#sm" "${QCONF}" > "${TMP_FILE}"
    sed -i 's/__POSTAUTH_TABLE__/${postauth_table}/g' "${TMP_FILE}"
else
    NEW_QUERY="${BLOCK_QUERY}" perl -0777 -pe 'BEGIN { $new = $ENV{"NEW_QUERY"}; }
        if (s#(Authentication Logging Queries.*?post-auth\s*\{.*?\bquery\s*=\s*")(?:(?:\\.|[^\"])*)("\s*)#$1$new$2#s) {
            $_;
        } else {
            s#(post-auth\s*\{.*?\bquery\s*=\s*")(?:(?:\\.|[^\"])*)("\s*)#$1$new$2#s;
        }
    ' "${QCONF}" > "${TMP_FILE}"
fi

if cmp -s "${QCONF}" "${TMP_FILE}"; then
    rm -f "${TMP_FILE}"
    echo "[WARN] No changes were made to ${QCONF}."
    exit 0
fi

cat "${TMP_FILE}" > "${QCONF}"
rm -f "${TMP_FILE}"

if [[ "${MODE}" == "legacy" ]]; then
    echo "[INFO] postauth_query updated in ${QCONF}"
    echo "[INFO] Verify with: grep -n \"postauth_query\" -A 8 ${QCONF}"
else
    echo "[INFO] post-auth query updated in ${QCONF}"
    echo "[INFO] Verify with: grep -n \"post-auth\" -A 12 ${QCONF}"
fi
echo "[INFO] Next: freeradius -CX && systemctl restart freeradius"
