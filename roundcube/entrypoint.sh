#!/bin/sh
set -e

mkdir -p /var/www/roundcube
tar -C /opt/roundcube -cf - . | tar -C /var/www/roundcube -xf -

cp /etc/roundcube/config.inc.php /var/www/roundcube/config/config.inc.php

mkdir -p /var/lib/roundcube/temp /var/lib/roundcube/enigma

php /var/www/roundcube/bin/initdb.sh --dir=/var/www/roundcube/SQL --update=1

chown -R www-data:www-data /var/lib/roundcube /var/www/roundcube

exec php-fpm8.4 --nodaemonize --fpm-config /etc/php/8.4/fpm/php-fpm.conf
