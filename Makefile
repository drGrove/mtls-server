SHELL := /bin/bash
DOCKER_REGISTRY ?= ""
TAG ?= latest

.PHONY: setup
setup:
	@pipenv install --three

.PHONY: setup-dev
setup-dev: set-hooks gen-secrets-folder
	@pipenv install --dev --three

.PHONY: requirements.txt
requirements.txt:
	@pipenv update
	@pipenv lock -r > requirements.txt

.PHONY: set-hooks
set-hooks:
	@echo "Setting commit hooks"
	@ ([ ! -L ".git/hooks/pre-commit" ] && ln -s $(PWD)/scripts/git-hooks/pre-commit.sh .git/hooks/pre-commit) || true

.PHONY: gen-secrets-folder
gen-secrets-folder:
	@./scripts/gen-secrets-folder

.PHONY: create-ca
create-ca: gen-secrets-folder
	@pipenv run python3 ./scripts/create-ca

.PHONY: create-pgp-key
create-pgp-key: gen-secrets-folder
	@./scripts/gen-gnupg-key

.PHONY: format
format:
	pipenv run black ./**/*.py

.PHONY: lint
lint:
	pipenv run flake8 ./**/*.py
	pipenv run black --check ./**/*.py

.PHONY: coverage
coverage:
	@pipenv run coverage report -m

.PHONY: coveralls
coveralls:
	@pipenv run coveralls

.PHONY: test
test:
ifeq "${CI}" ""
	-$(MAKE) stop-postgres
	$(MAKE) run-postgres
	@until pg_isready -h localhost -p 5432; do echo waiting for database; sleep 2; done
endif
	coverage run -m unittest -v
ifeq "${CI}" ""
	$(MAKE) stop-postgres
endif

.PHONY: test.dev
test.dev:
	pipenv run $(MAKE) test

.PHONY: test-by-name
test-by-name:
ifeq "${CI}" ""
	$(MAKE) run-postgres
	@until pg_isready -h localhost -p 5432; do echo waiting for database; sleep 2; done
endif
	-@coverage run -m unittest $(NAME) -v
ifeq "${CI}" ""
	$(MAKE) stop-postgres
endif

.PHONY: test-by-name.dev
test-by-name.dev:
	pipenv run $(MAKE) test-by-name

.PHONY: build-image
build-image:
	@docker build -t mtls-server:$(TAG) .

.PHONY: build-pypi
build-pypi:
	@pipenv run python setup.py sdist bdist_wheel

.PHONY: tag-image
tag-image: build-image
	@docker tag mtls-server:$(TAG) $(DOCKER_REGISTRY)mtls-server:$(TAG)
	@echo "Tagged image: $(DOCKER_REGISTRY)mtls-server:$(TAG)"

.PHONY: run-postgres
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

.PHONY: stop-postgres
stop-postgres:
	-docker stop mtls-postgres

.PHONY: run
run:
	@pipenv run python3 server.py

.PHONY: run-prod
run-prod: build-image run-postgres
	@docker run \
		--name mtls-server \
		--rm \
		-d \
		-v $(PWD)/secrets/gnupg:/home/mtls/secrets/gnupg \
		-v $(PWD)/secrets/gnupg_admin:/home/mtls/secrets/gnupg_admin \
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

.PHONY: stop-prod
stop-prod:
	@docker stop mtls-nginx
	@docker stop mtls-server
	@docker stop mtls-postgres

.PHONY: clean
clean:
	pipenv clean
	rm -r build dist mtls_server.egg-info

.PHONY: .drone.yml
.drone.yml:
	drone jsonnet --stream
	drone sign --save drGrove/mtls-server
