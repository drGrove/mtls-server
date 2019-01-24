.PHONY: setup clean lint create-ca build-image tag-image
SHELL := /bin/bash
DOCKER_REGISTRY ?= ""
TAG ?= latest

setup: set-hooks gen-secrets-folder
	@ ([ ! -d "env" ] && virtualenv --python python3 env) || true

set-hooks:
	@echo "Setting commit hooks"
	@ ([ ! -L ".git/hooks/pre-commit" ] && ln -s $(PWD)/scripts/git-hooks/pre-commit.sh .git/hooks/pre-commit) || true

gen-secrets-folder:
	@./scripts/gen-secrets-folder

create-ca: gen-secrets-folder
	./scripts/create-ca

create-pgp-key: gen-secrets-folder
	./scripts/gen-gnupg-key

install:
	@pip install -r requirements.txt

lint:
	@pycodestyle --first *.py

build-image:
	@docker build -t mtls-server:$(TAG) .

tag-image: build-image
	@docker tag mtls-server:$(TAG) $(DOCKER_REGISTRY)mtls-server:$(TAG)
	@echo "Tagged image: $(DOCKER_REGISTRY)mtls-server:$(TAG)"

run:
	@python3 server.py

run-prod:
	@docker run \
		--name mtls-server \
		--rm \
		-p 4000:4000 \
		-v $(PWD)/secrets/gnupg:/srv/secrets/gnupg \
		-v $(PWD)/secrets/certs/authority:/srv/secrets/certs/authority \
		-v $(PWD)/config.ini:/srv/config.ini \
		$(DOCKER_REGISTRY)mtls-server:$(TAG)

stop-prod:
	@docker stop mtls-server

clean:
	@rm -r env
