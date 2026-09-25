#!/bin/sh
set -e

cp /etc/roundcube/config.inc.php /opt/roundcube/config/config.inc.php

mkdir -p /var/lib/roundcube/temp /var/lib/roundcube/enigma /run/apache2

php /opt/roundcube/bin/initdb.sh --dir=/opt/roundcube/SQL --update=1

chown -R www-data:www-data /var/lib/roundcube

exec apache2 -d /etc/apache2 -D FOREGROUND
