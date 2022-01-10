SHELL := /bin/bash

test_env:
	docker compose -f docker-compose.test.yml up -d

test:
	docker compose -f docker-compose.test.yml exec test_api bash -c "yarn && yarn test:e2e"

migrate:
	docker compose exec api yarn knex migrate:latest

.PHONY: test migrate