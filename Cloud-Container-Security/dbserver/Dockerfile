# Use official MariaDB image for stability and security
FROM mariadb:10.11

# Copy secure custom config for hardening (bind-address, SQL modes, etc.)
COPY sqlconfig/mysqld.cnf /etc/mysql/conf.d/mysqld.cnf

# Copy the database schema and data
COPY sqlconfig/csvs23db.sql /docker-entrypoint-initdb.d/


# Use non-root mysql user by default (UID 999)
USER 999


