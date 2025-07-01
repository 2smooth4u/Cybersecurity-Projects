# -------------------------
# Metadata
# -------------------------
IMAGE_NAME=u5645801/csvs_webserver_i
CONTAINER_NAME=u5645801_csvs_webserver_c
NETWORK_NAME=u5645801_net
SUBNET=192.168.56.0/24
CONTAINER_IP=192.168.56.103

# -------------------------
# Build the Docker image
# -------------------------
build:
	docker build -t $(IMAGE_NAME) .

# -------------------------
# Run the container securely
# -------------------------
run:
	docker volume create u5645801_csvs_webserver_c_data || true
	docker network create --subnet=192.168.56.0/24 u5645801_net || true
	docker rm -f u5645801_csvs_webserver_c || true
	docker run -d \
		--read-only \
		--cap-drop=ALL \
		--tmpfs /tmp:rw,nosuid,nodev \
		--tmpfs /run:rw,nosuid,nodev,uid=1001,gid=1001 \
		--tmpfs /run/php:rw,nosuid,nodev,uid=1001,gid=1001 \
		--tmpfs /var/log/php-fpm:rw,nosuid,nodev,uid=1001,gid=1001 \
		--tmpfs /var/log/nginx:rw,nosuid,nodev,uid=1001,gid=1001 \
		--tmpfs /var/lib/nginx/body:rw,nosuid,nodev,uid=1001,gid=1001 \
		--tmpfs /var/lib/nginx/proxy:rw,nosuid,nodev,uid=1001,gid=1001 \
		--tmpfs /var/lib/nginx/fastcgi:rw,nosuid,nodev,uid=1001,gid=1001 \
		--tmpfs /var/lib/nginx/uwsgi:rw,nosuid,nodev,uid=1001,gid=1001 \
		--tmpfs /var/lib/nginx/scgi:rw,nosuid,nodev,uid=1001,gid=1001 \
		--pids-limit=200 \
		--user 1001:1001 \
		-p 80:80 \
		--security-opt no-new-privileges:true \
		--security-opt no-new-privileges:true \
		--network u5645801_net \
		--ip 192.168.56.103 \
		--name u5645801_csvs_webserver_c \
		u5645801/csvs_webserver_i









# -------------------------
# Stop and remove container
# -------------------------
clean:
	docker rm -f $(CONTAINER_NAME) || true

# -------------------------
# Remove image (use cautiously)
# -------------------------
rmi:
	docker rmi $(IMAGE_NAME) || true

