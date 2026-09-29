# Dependency runtime reused by the focused local validation and final image.
FROM php:8.3-fpm-alpine@sha256:454b11c8907e32878ce92e87b13c14e1bbe6e1b10f4f96d4a19c9b62ec675d41 AS runtime-base
WORKDIR /var/www/html
RUN apk add --no-cache dumb-init shadow sqlite-dev libpng-dev libjpeg-turbo-dev freetype-dev curl icu-dev icu-data-full nginx dcron tzdata libzip-dev sqlite libwebp-dev \
    && docker-php-ext-configure gd --with-freetype --with-jpeg --with-webp \
    && docker-php-ext-install -j2 pdo pdo_sqlite calendar gd intl zip

FROM composer:2@sha256:9715c7f69044da2a212a5fbde29ee7da24e364d426560ae6367b060236f847d7 AS composer-bin
FROM runtime-base AS dependencies
COPY --from=composer-bin /usr/bin/composer /usr/local/bin/composer
COPY composer.json composer.lock ./
RUN composer install --no-dev --prefer-dist --no-progress --no-interaction --classmap-authoritative --no-scripts

FROM runtime-base AS application-source
COPY . .
# Streamed git-archive contexts do not apply the client-side .dockerignore.
# Keep development files out of the final runtime for either context form.
RUN rm -rf .github tests test-results screenshots dev .tmp \
    && rm -f *.md .dockerignore .gitignore .gitattributes Dockerfile

FROM runtime-base AS runtime
COPY --from=application-source /var/www/html /var/www/html
COPY --from=dependencies /var/www/html/vendor ./vendor
COPY nginx.conf /etc/nginx/nginx.conf
COPY nginx.default.conf /etc/nginx/http.d/wallos.conf.template
RUN rm -f /etc/nginx/http.d/default.conf \
    && dos2unix /var/www/html/startup.sh /var/www/html/cronjobs /etc/nginx/nginx.conf /etc/nginx/http.d/wallos.conf.template \
    && mkdir -p /var/log/cron /var/run/php /var/lib/nginx /var/lib/php/sessions \
    && chmod +x startup.sh \
    && printf '[www]\nlisten = /var/run/php/wallos.sock\nlisten.owner = www-data\nlisten.group = www-data\nlisten.mode = 0660\npm.max_children = 3\npm.start_servers = 1\npm.min_spare_servers = 1\npm.max_spare_servers = 2\npm.max_requests = 300\nclear_env = no\nphp_admin_value[auto_prepend_file] = /var/www/html/includes/homelab_prepend.php\nphp_admin_value[session.save_path] = /var/lib/php/sessions\n' > /usr/local/etc/php-fpm.d/zz-homelab.conf \
    && printf 'upload_max_filesize=16M\npost_max_size=20M\nexpose_php=Off\ndisplay_errors=Off\nlog_errors=On\nsession.use_strict_mode=1\n' > /usr/local/etc/php/conf.d/homelab.ini
ENV HOMELAB_ENABLED=1 WALLOS_BIND=127.0.0.1 WALLOS_PORT=18081 PUID=1001 PGID=1001 TZ=Asia/Shanghai
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 CMD curl -fsS "http://127.0.0.1:${WALLOS_PORT}/apps/wallos/health.php" >/dev/null || exit 1
ENTRYPOINT ["dumb-init", "--"]
CMD ["/var/www/html/startup.sh"]
