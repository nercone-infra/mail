#!/bin/sh
set -e

certificates() {
    cat /etc/certs/letsencrypt/fullchain.pem /etc/certs/letsencrypt/privkey.pem 2> /dev/null | sha256sum
}

install_certificates() {
    mkdir -p /etc/postfix/tls
    cp /etc/certs/letsencrypt/fullchain.pem /etc/postfix/tls/fullchain.pem
    cp /etc/certs/letsencrypt/privkey.pem   /etc/postfix/tls/privkey.pem
    chown root:postfix /etc/postfix/tls/*.pem
    chmod 640 /etc/postfix/tls/*.pem
}

cp /etc/postfix.d/main.cf       /etc/postfix/main.cf
cp /etc/postfix.d/master.cf     /etc/postfix/master.cf
cp /etc/postfix.d/header_checks /etc/postfix/header_checks
cp /etc/postfix.d/openssl.cnf   /etc/postfix/openssl.cnf

mkdir -p /etc/postfix/pgsql
for template in /etc/postfix.d/pgsql/*.cf; do
    rendered="/etc/postfix/pgsql/$(basename "${template}")"
    envsubst '${MAIL_DB_PASSWORD}' < "${template}" > "${rendered}"
    chown root:postfix "${rendered}"
    chmod 640 "${rendered}"
done

until [ -s /etc/certs/letsencrypt/fullchain.pem ] && [ -s /etc/certs/letsencrypt/privkey.pem ]; do
    echo "postfix: waiting for the Let's Encrypt certificate" >&2
    sleep 10
done
install_certificates

postfix check

(
    set +e
    CURRENT=$(certificates)
    while sleep 60; do
        NEXT=$(certificates)
        if [ "${NEXT}" != "${CURRENT}" ]; then
            install_certificates
            postfix reload
            CURRENT="${NEXT}"
        fi
    done
) &

exec postfix start-fg
