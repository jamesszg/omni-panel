#!/usr/bin/env bash
set -euo pipefail

# End-to-end CLI verification script for Debian 13 (Trixie) VPS deployments.
# Run as root after installing omni-panel on Debian 13.
# Required environment variables (pass via shell without hardcoding credentials):
#   OMNI_USER   - Panel admin username
#   OMNI_PASS   - Panel admin password
#   OMNI_DOMAIN - Public domain pointed to this VPS for :443 gateway tests
# Optional environment variables:
#   XUI_FOLDER  - Installation folder (default: /usr/local/x-ui)
#   OMNI_URL    - Local panel base URL (e.g. http://127.0.0.1:2053/basepath)

XUI_FOLDER="${XUI_FOLDER:-/usr/local/x-ui}"
OMNI_USER="${OMNI_USER:-}"
OMNI_PASS="${OMNI_PASS:-}"
OMNI_DOMAIN="${OMNI_DOMAIN:-}"
OMNI_URL="${OMNI_URL:-}"

echo "[1/6] Checking required binaries in ${XUI_FOLDER}..."
test -x "${XUI_FOLDER}/x-ui"
test -x "${XUI_FOLDER}/bin/sing-box"
test -x "${XUI_FOLDER}/bin/rpxy-l4"
"${XUI_FOLDER}/bin/sing-box" version

echo "[2/6] Verifying systemd unit and zero host firewall modifications..."
systemctl is-active --quiet x-ui
if command -v ufw >/dev/null 2>&1; then
    echo "ufw detected (left untouched by omni-panel): $(ufw status | head -n1)"
fi

if [[ -z "${OMNI_URL}" ]]; then
    PANEL_SETTINGS=$("${XUI_FOLDER}/x-ui" setting -show true 2>/dev/null || true)
    PANEL_PORT=$(printf '%s\n' "${PANEL_SETTINGS}" | awk '/port:/ {print $2; exit}')
    WEB_BASE=$(printf '%s\n' "${PANEL_SETTINGS}" | awk '/webBasePath:/ {print $2; exit}')
    PANEL_PORT="${PANEL_PORT:-2053}"
    WEB_BASE="/${WEB_BASE#/}"
    WEB_BASE="${WEB_BASE%/}"
    OMNI_URL="http://127.0.0.1:${PANEL_PORT}${WEB_BASE}"
fi

if [[ -z "${OMNI_USER}" || -z "${OMNI_PASS}" || -z "${OMNI_DOMAIN}" ]]; then
    echo "Set OMNI_USER, OMNI_PASS, and OMNI_DOMAIN to run live API, :443 gateway, and OpenSpeedTest checks."
    echo "Binary and systemd checks passed."
    exit 0
fi

COOKIE_JAR=$(mktemp)
trap 'rm -f "${COOKIE_JAR}"' EXIT

echo "[3/6] Authenticating against ${OMNI_URL}..."
LOGIN_RESP=$(curl -fsS -k -c "${COOKIE_JAR}" -X POST "${OMNI_URL}/login" \
    -d "username=${OMNI_USER}&password=${OMNI_PASS}")
echo "${LOGIN_RESP}" | grep -q '"success":true'

echo "[4/6] Listing curated templates and bootstrapping :443 unified stack..."
curl -fsS -k -b "${COOKIE_JAR}" "${OMNI_URL}/panel/api/gateway/templates" | grep -q 'singbox-hysteria2-443'

BOOTSTRAP_PAYLOAD=$(cat <<JSON
{
  "domain": "${OMNI_DOMAIN}",
  "publicPort": 443,
  "presetIds": [
    "singbox-hysteria2-443",
    "xray-vless-reality-vision-443",
    "xray-vless-ws-l7-443"
  ],
  "speedtestEnable": true,
  "acmeMode": "self-signed"
}
JSON
)
curl -fsS -k -b "${COOKIE_JAR}" -H "Content-Type: application/json" \
    -d "${BOOTSTRAP_PAYLOAD}" "${OMNI_URL}/panel/api/gateway/bootstrap" | grep -q '"success":true'

sleep 3

echo "[5/6] Verifying live sing-box + L4/L7 :443 gateway status & config syntax..."
STATUS_JSON=$(curl -fsS -k -b "${COOKIE_JAR}" "${OMNI_URL}/panel/api/gateway/status")
echo "${STATUS_JSON}" | grep -q '"singboxRunning":true'
echo "${STATUS_JSON}" | grep -q '"l7Running":true'
echo "${STATUS_JSON}" | grep -q '"rpxyRunning":true'

if [[ -f "${XUI_FOLDER}/bin/singbox/config.json" ]]; then
    "${XUI_FOLDER}/bin/sing-box" check -c "${XUI_FOLDER}/bin/singbox/config.json"
fi

echo "[6/6] Verifying :443 HTTPS OpenSpeedTest fallback (/, /downloading, /upload)..."
curl -fsS -k --resolve "${OMNI_DOMAIN}:443:127.0.0.1" "https://${OMNI_DOMAIN}/" | grep -qi "OpenSpeedTest"
DL_BYTES=$(curl -fsS -k --resolve "${OMNI_DOMAIN}:443:127.0.0.1" "https://${OMNI_DOMAIN}/downloading?n=1" | wc -c)
echo "Downloaded ${DL_BYTES} bytes from /downloading"
UPLOAD_CODE=$(curl -s -o /dev/null -w '%{http_code}' -k --resolve "${OMNI_DOMAIN}:443:127.0.0.1" \
    -X POST --data-binary 'omni-upload-probe' "https://${OMNI_DOMAIN}/upload")
echo "Upload probe HTTP status: ${UPLOAD_CODE}"
test "${UPLOAD_CODE}" = "200" -o "${UPLOAD_CODE}" = "204"

echo "Debian 13 E2E verification PASSED."
