#!/bin/sh
exec curl -s -o /dev/null -H @/etc/dovecot/rspamd-password --data-binary @- http://127.0.0.1:11334/learnspam
