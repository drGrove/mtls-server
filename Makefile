.PHONY: setup clean lint create-ca build-image tag-image
SHELL := /bin/bash
DOCKER_REGISTRY ?= ""
TAG ?= latest

PIP_ENV := $(shell pipenv --venv)

setup:
	@pipenv install

setup-dev: set-hooks gen-secrets-folder
	@pipenv install --dev

pipenv-lock:
	@pipenv update
	@pipenv lock -r > requirements.txt

set-hooks:
	@echo "Setting commit hooks"
	@ ([ ! -L ".git/hooks/pre-commit" ] && ln -s $(PWD)/scripts/git-hooks/pre-commit.sh .git/hooks/pre-commit) || true

gen-secrets-folder:
	@./scripts/gen-secrets-folder

create-ca: gen-secrets-folder
	@$(PIP_ENV)/bin/python3 ./scripts/create-ca

create-pgp-key: gen-secrets-folder
	@./scripts/gen-gnupg-key

format:
	@pipenv run black -l 90 ./*.py

lint:
	@pipenv run pycodestyle --max-line-length=90 ./*.py

coverage:
	@$(PIP_ENV)/bin/coverage report -m

coveralls:
	@$(PIP_ENV)/bin/coveralls

test:
ifeq "${CI}" ""
	$(MAKE) run-postgres
	@until pg_isready -h localhost -p 5432; do echo waiting for database; sleep 2; done
endif
	-@$(PIP_ENV)/bin/coverage run -m unittest -v
ifeq "${CI}" ""
		@docker stop mtls-postgres
endif

test-by-name:
ifeq "${CI}" ""
	$(MAKE) run-postgres
	@until pg_isready -h localhost -p 5432; do echo waiting for database; sleep 2; done
endif
	-@$(PIP_ENV)/bin/coverage run -m unittest $(TEST) -v
ifeq "${CI}" ""
		@docker stop mtls-postgres
endif

build-image:
	@docker build -t mtls-server:$(TAG) .

tag-image: build-image
	@docker tag mtls-server:$(TAG) $(DOCKER_REGISTRY)mtls-server:$(TAG)
	@echo "Tagged image: $(DOCKER_REGISTRY)mtls-server:$(TAG)"

run-postgres:
	@docker run \
		--name mtls-postgres \
		--rm \
		-d \
		-e POSTGRES_DB=mtls \
		-e POSTGRES_PASSWORD=mtls \
		-e POSTGRES_HOST_AUTH_METHOD=trust \
		-p 5432:5432 \
		postgres

run:
	@. $(PIP_ENV)/bin/activate
	@$(PIP_ENV)/bin/python3 server.py

run-prod: build-image run-postgres
	@docker run \
		--name mtls-server \
		--rm \
		-d \
		-v $(PWD)/secrets/gnupg:/home/mtls/secrets/gnupg \
		-v $(PWD)/secrets/certs/authority:/home/mtls/secrets/certs/authority \
		-v $(PWD)/config.ini:/home/mtls/config.ini \
		$(DOCKER_REGISTRY)mtls-server:$(TAG)
	@docker run \
		--name mtls-nginx \
		--rm \
		-d \
		-p 443:443 \
		--link mtls-server:mtls \
		-v $(PWD)/nginx/nginx.conf:/etc/nginx/nginx.conf \
		-v $(PWD)/nginx/includes:/etc/nginx/includes \
		-v $(PWD)/secrets/certs/authority:/etc/nginx/ssl/client_certs/ \
		-v $(PWD)/nginx/html:/usr/share/nginx/ \
		nginx


stop-prod:
	@docker stop mtls-nginx
	@docker stop mtls-server
	@docker stop mtls-postgres

clean:
	@rm -r $(PIP_ENV)
