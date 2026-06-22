.RECIPEPREFIX = >

# Taken from https://github.com/wazuh/wazuh-docker.git on branch "v4.14.5"
WAZUH_REGISTRY=docker.io
IMAGE_TAG=4.14.5
WAZUH_IMAGE_VERSION=4.14.5
WAZUH_TAG_REVISION=1
target=0.0.0.0:8080

build-agent:
> cd ./config/wazuh_agent/build && \
    docker build --no-cache -t "$(WAZUH_REGISTRY)/wazuh/wazuh-agent:$(IMAGE_TAG)" \
    --build-arg WAZUH_VERSION="$(WAZUH_IMAGE_VERSION)" \
    --build-arg WAZUH_TAG_REVISION="$(WAZUH_TAG_REVISION)" .

certs: generate-indexer-certs.yml
> docker compose -f generate-indexer-certs.yml run --rm generator

up: docker-compose.yml
> docker-compose up -d --remove-orphans

down: docker-compose.yml
> docker-compose down

clean:
> docker system prune -f && docker volume prune -f

stop: down clean
restart: stop up status

ddos:
> for i in {1..100}; do curl -s -o /dev/null http://$(target); done

status:
> docker-compose ps

sh-agent:
> docker exec -ti fp_soc_07-wazuh.agent-1 bash

sh-manager:
> docker exec -ti fp_soc_07-wazuh.manager-1 bash

log-manager:
> docker exec -ti fp_soc_07-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
