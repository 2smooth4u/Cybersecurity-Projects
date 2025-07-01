# --------------------------------------------------------------------
# Base image - Debian slim for minimal footprint and better security
# --------------------------------------------------------------------
FROM debian:bullseye-slim

# --------------------------------------------------------------------
# Install required packages (nginx, PHP, FPM, MySQL support)
# --------------------------------------------------------------------
RUN apt-get update && apt-get install -y \
    nginx \
    php-fpm \
    php-mysql \
    curl \
    unzip \
    supervisor \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# --------------------------------------------------------------------
# Create non-root user
# --------------------------------------------------------------------
RUN useradd -m -u 1001 -s /bin/bash webapp

# --------------------------------------------------------------------
# Copy web application files
# --------------------------------------------------------------------
COPY webfiles/ /var/www/html/
RUN chown -R webapp:webapp /var/www/html && \
    chmod -R 750 /var/www/html

# Create and assign correct ownership to required runtime directories
RUN mkdir -p /var/log/php-fpm /run/php && \
    chown -R 1001:1001 /var/log/php-fpm /run/php


# --------------------------------------------------------------------
# Copy and apply configuration files
# --------------------------------------------------------------------
COPY configfiles/nginx.conf /etc/nginx/nginx.conf
COPY configfiles/default.conf /etc/nginx/sites-enabled/default
COPY configfiles/php.ini /etc/php/7.4/fpm/php.ini
COPY configfiles/php-fpm.conf /etc/php/7.4/fpm/php-fpm.conf
COPY configfiles/www.conf /etc/php/7.4/fpm/pool.d/www.conf

# Fix permissions for PHP config files to allow non-root execution
RUN chmod 644 /etc/php/7.4/fpm/php-fpm.conf \
    && chmod 644 /etc/php/7.4/fpm/pool.d/www.conf

RUN mkdir -p /run/php && chown 1001:1001 /run/php


# Copy secure entrypoint
COPY docker-entrypoint.sh /docker-entrypoint.sh

# Make it executable by all (required for non-root user to execute it)
RUN chmod 755 /docker-entrypoint.sh

# --------------------------------------------------------------------
# Expose necessary port for HTTP
# --------------------------------------------------------------------
EXPOSE 80

# --------------------------------------------------------------------
# Use hardened entrypoint
# --------------------------------------------------------------------
ENTRYPOINT ["/docker-entrypoint.sh"]

