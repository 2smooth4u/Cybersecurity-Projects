# Makefile for building and running the hardened DB container
# Author: u5645801

IMAGE_NAME = u5645801/csvs_dbserver_i
CONTAINER_NAME = u5645801_csvs_dbserver_c
VOLUME_NAME = u5645801_dbdata
NETWORK_NAME = u5645801_net
IP_ADDR = 192.168.56.102

# Build the DB server image
build:
	docker build -t $(IMAGE_NAME) .

# Clean old container if it exists
clean:
	docker rm -f $(CONTAINER_NAME) || true

# Create volume and network (if not exists), then run hardened container
run: clean
	docker volume create $(VOLUME_NAME) || true
	docker network create --subnet=192.168.56.0/24 $(NETWORK_NAME) || true
	docker run -d \
		--read-only \
		--cap-drop=ALL \
		--user 999:999 \
		--pids-limit=200 \
		--security-opt no-new-privileges:true \
		--security-opt seccomp=unconfined \
		--tmpfs /tmp:rw,nosuid,nodev \
		--tmpfs /run \
		--tmpfs /var/run/mysqld:rw,uid=999,gid=999 \
		--mount type=volume,source=$(VOLUME_NAME),target=/var/lib/mysql \
		--network $(NETWORK_NAME) \
		--ip $(IP_ADDR) \
		-e MYSQL_ROOT_PASSWORD="CorrectHorseBatteryStaple" \
		-e MYSQL_DATABASE=csvs23db \
		--name $(CONTAINER_NAME) \
		$(IMAGE_NAME)

# Stop and remove container and network
purge:
	docker rm -f $(CONTAINER_NAME) || true
	docker volume rm $(VOLUME_NAME) || true
	docker network rm $(NETWORK_NAME) || true

