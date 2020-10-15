#!/bin/bash

echo "Importing USER PGP keys"
GNUPGHOME="${USER_GNUPGHOME}" gpg --import "${USER_SEED_FOLDER}"/*

echo "Trusting USER PGP keys"
for fpr in $(GNUPGHOME="${USER_GNUPGHOME}" gpg --list-keys --with-colons | awk -F: '/fpr:/ {print $10}' | sort -u); do
    echo "${fpr}:6:" | GNUPGHOME="${USER_GNUPGHOME}" gpg --import-ownertrust;
done

echo "Importing ADMIN PGP keys"
GNUPGHOME="${ADMIN_GNUPGHOME}" gpg --import "${ADMIN_SEED_FOLDER}"/*

echo "Trusting ADMIN PGP keys"
for fpr in $(GNUPGHOME="${ADMIN_GNUPGHOME}" gpg --list-keys --with-colons | awk -F: '/fpr:/ {print $10}' | sort -u); do
    echo "${fpr}:6:" | GNUPGHOME="${ADMIN_GNUPGHOME}" gpg --import-ownertrust;
done
