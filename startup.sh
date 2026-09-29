#!/bin/sh
set -eu
PUID=${PUID:-1001}
PGID=${PGID:-1001}
WALLOS_BIND=${WALLOS_BIND:-127.0.0.1}
WALLOS_PORT=${WALLOS_PORT:-18081}
case "$PUID:$PGID:$WALLOS_PORT" in *[!0-9:]*|'') echo "Invalid numeric runtime setting" >&2; exit 1;; esac
case "$WALLOS_BIND" in 127.0.0.1|0.0.0.0) ;; *) echo "Invalid bind address" >&2; exit 1;; esac
[ "$WALLOS_PORT" -gt 1024 ] && [ "$WALLOS_PORT" -lt 65536 ]
[ "${HOMELAB_ENABLED:-}" = 1 ] || { echo "Platform mode is required" >&2; exit 1; }
# A missing bind directory must fail before initialization, never create a fallback.
[ -d /var/www/html/db ] && [ -d /var/www/html/images/uploads/logos ]
rm -f /tmp/wallos-ready
groupmod -o -g "$PGID" www-data
usermod -o -u "$PUID" www-data
mkdir -p /var/www/html/images/uploads/logos/avatars /var/lib/php/sessions /var/run/php
chown -R "$PUID:$PGID" /var/www/html/db /var/www/html/images/uploads/logos /var/lib/php/sessions
chmod 0750 /var/www/html/db /var/www/html/images/uploads/logos /var/lib/php/sessions
umask 027
# No web listener exists until schema and platform bootstrap have succeeded.
php /var/www/html/endpoints/cronjobs/createdatabase.php >/dev/null
php /var/www/html/endpoints/db/migrate.php >/dev/null
php /var/www/html/includes/homelab_bootstrap.php
rm -f /var/www/html/db/setup_token.db
chown -R "$PUID:$PGID" /var/www/html/db
find /var/www/html/db -type f -exec chmod 0640 {} +
sed -e "s/__BIND__/$WALLOS_BIND/g" -e "s/__PORT__/$WALLOS_PORT/g" /etc/nginx/http.d/wallos.conf.template > /etc/nginx/http.d/wallos.conf
nginx -t
# Only requested local subscription/annual-statistics maintenance; no email/reset/push agents.
crontab -u www-data /var/www/html/cronjobs
PHP_FPM_PID=
NGINX_PID=
CROND_PID=
stop() {
    trap - TERM INT
    rm -f /tmp/wallos-ready
    [ -z "$NGINX_PID" ] || kill -QUIT "$NGINX_PID" 2>/dev/null || true
    [ -z "$PHP_FPM_PID" ] || kill -QUIT "$PHP_FPM_PID" 2>/dev/null || true
    [ -z "$CROND_PID" ] || kill -TERM "$CROND_PID" 2>/dev/null || true
    wait || true
}
trap stop TERM INT
php-fpm -F &
PHP_FPM_PID=$!
crond -f -L /dev/stderr &
CROND_PID=$!
nginx -g 'daemon off;' &
NGINX_PID=$!
touch /tmp/wallos-ready
chmod 0644 /tmp/wallos-ready
# Exit the whole App if any supervised process fails; systemd owns restart.
wait -n "$PHP_FPM_PID" "$NGINX_PID" "$CROND_PID" || true
stop
exit 1
