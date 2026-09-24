#!/usr/bin/env bash
set -e

DOMAIN="${1:-nercone.dev}"
SELECTOR="${2:-$(date +%Y%m%d)}"

cd "$(dirname "$0")"

DKIM_DIR="$(pwd)/data/rspamd/dkim"
KEY_NAME="${DOMAIN}.${SELECTOR}.key"
KEY_PATH="/var/lib/rspamd/dkim/${KEY_NAME}"
SELECTORS_MAP="${DKIM_DIR}/selectors.map"

echo "Domain: ${DOMAIN}"
echo "Selector: ${SELECTOR}"

echo
echo "> Generate DKIM Key"

if [ -f "${DKIM_DIR}/${KEY_NAME}" ]; then
    echo "DKIM key exists: ${DKIM_DIR}/${KEY_NAME}"
else
    docker compose exec -T rspamd rspamadm dkim_keygen -b 3072 -s "${SELECTOR}" -d "${DOMAIN}" -k "${KEY_PATH}" > /dev/null
    docker compose exec -T rspamd chown _rspamd:_rspamd "${KEY_PATH}"
    docker compose exec -T rspamd chmod 600 "${KEY_PATH}"
    echo "DKIM key generated: ${DKIM_DIR}/${KEY_NAME}"
fi

echo
echo "> Generate TXT Record"

PUBLIC_KEY=$(docker compose exec -T rspamd sh -c "/usr/local/bin/openssl rsa -in ${KEY_PATH} -pubout -outform DER 2>/dev/null | base64 | tr -d '\n'")
if [ -z "${PUBLIC_KEY}" ]; then
    echo "Public key not readable: ${DKIM_DIR}/${KEY_NAME}" >&2
    exit 1
fi

printf "%-40s TXT \"%s\"\n" "${SELECTOR}._domainkey.${DOMAIN}." "v=DKIM1; k=rsa; p=${PUBLIC_KEY}"

echo
echo "> Activate Selector"

PREVIOUS_SELECTOR=$(sudo grep -E "^${DOMAIN}[[:space:]]" "${SELECTORS_MAP}" 2> /dev/null | awk '{print $2}' || true)

sudo touch "${SELECTORS_MAP}"
sudo sed -i "/^${DOMAIN}[[:space:]]/d" "${SELECTORS_MAP}"
echo "${DOMAIN} ${SELECTOR}" | sudo tee -a "${SELECTORS_MAP}" > /dev/null
echo "Selector activated: ${DOMAIN} -> ${SELECTOR}"

echo
echo "> Remove Previous Key"

if [ -z "${PREVIOUS_SELECTOR}" ] || [ "${PREVIOUS_SELECTOR}" = "${SELECTOR}" ]; then
    echo "No previous key to remove."
else
    PREVIOUS_KEY_NAME="${DOMAIN}.${PREVIOUS_SELECTOR}.key"
    PREVIOUS_KEY_PATH="/var/lib/rspamd/dkim/${PREVIOUS_KEY_NAME}"

    if [ -f "${DKIM_DIR}/${PREVIOUS_KEY_NAME}" ]; then
        docker compose exec -T rspamd rm -f "${PREVIOUS_KEY_PATH}"
        echo "DKIM key removed: ${DKIM_DIR}/${PREVIOUS_KEY_NAME}"
    else
        echo "DKIM key not found: ${DKIM_DIR}/${PREVIOUS_KEY_NAME}"
    fi
fi

echo
echo "> Restart Rspamd"

docker compose exec rspamd rspamadm configtest
docker compose restart rspamd
