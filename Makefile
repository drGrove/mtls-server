.PHONY: setup clean lint create-ca
SHELL := /bin/bash

setup: set-hooks gen-secrets-folder
	@ ([ ! -d "env" ] && python3 -m virtualenv env) || true

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

clean:
	@rm -r env
