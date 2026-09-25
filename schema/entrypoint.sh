#!/bin/sh
set -u

until psql -q -v ON_ERROR_STOP=1 -h 127.0.0.1 -U mail -d mail -f /usr/local/lib/schema/mail.sql; do
    echo "schema: waiting for the database" >&2
    sleep 10
done
