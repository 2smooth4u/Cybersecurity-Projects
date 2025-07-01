#!/bin/bash

########################################################################
# docker-entrypoint.sh
# Hardened entrypoint for web server container
# Responsible for launching nginx and php-fpm securely
########################################################################

# Exit immediately if any command fails
set -e

# Create log directories if not exist (useful in hardened setups)
mkdir -p /var/log/php-fpm /run/php
chown -R webapp:webapp /var/log/php-fpm /run/php

# Start PHP-FPM in the background
php-fpm7.4 --nodaemonize --fpm-config /etc/php/7.4/fpm/php-fpm.conf &

# Start NGINX in the foreground
nginx -g 'daemon off;'

