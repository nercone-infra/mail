#!/bin/sh
set -e

if [ -z "${RSPAMD_PASSWORD}" ]; then
    echo "RSPAMD_PASSWORD is required" >&2
    exit 1
fi

if [ -z "${REDIS_PASSWORD}" ]; then
    echo "REDIS_PASSWORD is required" >&2
    exit 1
fi

rm -rf /etc/rspamd/local.d /etc/rspamd/override.d
cp -a /etc/rspamd.d/local.d    /etc/rspamd/local.d
cp -a /etc/rspamd.d/override.d /etc/rspamd/override.d

RSPAMD_PASSWORD_HASH="$(rspamadm pw -p "${RSPAMD_PASSWORD}")"
export RSPAMD_PASSWORD_HASH
envsubst '${RSPAMD_PASSWORD_HASH}' \
    < /etc/rspamd.d/local.d/worker-controller.inc \
    > /etc/rspamd/local.d/worker-controller.inc

envsubst '${REDIS_PASSWORD}' \
    < /etc/rspamd.d/local.d/redis.conf \
    > /etc/rspamd/local.d/redis.conf

mkdir -p /var/lib/rspamd/dkim
[ -f /var/lib/rspamd/dkim/selectors.map ] || touch /var/lib/rspamd/dkim/selectors.map
chown -R _rspamd:_rspamd /var/lib/rspamd

exec rspamd -f -u _rspamd -g _rspamd
