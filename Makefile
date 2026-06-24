.RECIPEPREFIX = >

# Taken from https://github.com/wazuh/wazuh-docker.git on branch "v4.14.5"
WAZUH_REGISTRY=docker.io
WAZUH_IMAGE_VERSION=4.14.5
WAZUH_TAG_REVISION=1
FILEBEAT_MODULE_VERSION="0.5"
WAZUH_FILEBEAT_MODULE="wazuh-filebeat-${FILEBEAT_MODULE_VERSION}.tar.gz"
FILEBEAT_TEMPLATE_BRANCH=4.5
target=0.0.0.0:8082

build-agent:
> cd ./config/wazuh_agent/build && \
    docker build --no-cache -t "$(WAZUH_REGISTRY)/wazuh/wazuh-agent:$(WAZUH_IMAGE_VERSION)" \
    --build-arg WAZUH_VERSION="$(WAZUH_IMAGE_VERSION)" \
    --build-arg WAZUH_TAG_REVISION="$(WAZUH_TAG_REVISION)" .

build-manager:
> cd ./config/wazuh_cluster/build && \
    docker build --no-cache -t "$(WAZUH_REGISTRY)/wazuh/wazuh-manager:$(WAZUH_IMAGE_VERSION)" \
    --build-arg WAZUH_VERSION="$(WAZUH_IMAGE_VERSION)" \
    --build-arg WAZUH_TAG_REVISION="$(WAZUH_TAG_REVISION)" \
    --build-arg FILEBEAT_TEMPLATE_BRANCH="${FILEBEAT_TEMPLATE_BRANCH}" \
    --build-arg WAZUH_FILEBEAT_MODULE="${WAZUH_FILEBEAT_MODULE}" .

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
> for i in {1..100}; do curl -s -o /dev/null http://$(target) ; done

ddos-view: 
> docker exec fp_soc_07-wazuh.manager-1 cat /var/ossec/logs/active-responses.log

malw:
> docker exec fp_soc_07-wazuh.agent-1 bash -c 'echo "spooki" > /tmp/backdoor.sh' && \
    docker exec fp_soc_07-wazuh.agent-1 bash -c 'echo "spooki" > /usr/share/nginx/html/shell.php'

social:
> docker exec fp_soc_07-wazuh.agent-1 bash -c 'logger "curl http://10.0.0.0/payload executed by compromised user"'

ai:
> docker exec fp_soc_07-wazuh.manager-1 bash -c "cat /var/ossec/logs/alerts/alerts.json" > alerts_raw.json && \
    cd ./ai_model && pip install scikit-learn pandas numpy joblib && python train_model.py && python wazuh_integration.py --batch

status:
> docker-compose ps

sh-agent:
> docker exec -ti fp_soc_07-wazuh.agent-1 bash

sh-manager:
> docker exec -ti fp_soc_07-wazuh.manager-1 bash

log-manager:
> docker exec -ti fp_soc_07-wazuh.manager-1 /var/ossec/bin/wazuh-logtest

run-agent:
> docker run -ti wazuh/wazuh-agent:$(WAZUH_IMAGE_VERSION) bash
