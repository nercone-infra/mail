#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

sudo git pull

docker compose restart postfix dovecot rspamd roundcube
