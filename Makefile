.RECIPEPREFIX = >
up:
> docker-compose up -d --remove-orphans

down:
> docker-compose down

clean:
> docker system prune -f && docker volume prune -f

stop: down clean
restart: stop up status

stress:
> for i in {1..100}; do curl -s http://0.0.0.0:8080 >/dev/null; done

status:
> docker-compose ps

agent:
> docker exec -ti fp_soc_07-wazuh.agent-1 bash
