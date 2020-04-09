# mTLS Server #

[![Build Status](https://travis-ci.org/drGrove/mtls-server.svg?branch=master)](https://travis-ci.org/drGrove/mtls-server)
[![Known Vulnerabilities](https://snyk.io/test/github/drGrove/mtls-server/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/drGrove/mtls-server?targetFile=requirements.txt)
[![Coverage Status](https://coveralls.io/repos/github/drGrove/mtls-server/badge.svg?branch=master)](https://coveralls.io/github/drGrove/mtls-server?branch=master)

A mutual TLS (mTLS) system for authenticating users to services that need to be on the internet, but should only be
accessible to users that specifically need it. This should be used as a initial security measure on top of normal login
to handle multi-factor authentication.

This server contains an API for converting Certificate Signing Requests (CSRs) into client certificates. The user
database is PGPs trust database to verify detached signatures of the underlying CSR and generats a new client
certificate. This client certificate will have a default lifetime of 18 hours, but can be configured to have a longer
time to live (TTL). Admin calls are authenticated against a secondary PGP trust database of signed requests for managing
the Certificate Revocation List (CRL).

This project is based on the whitepapers for [Beyond Corp](https://www.beyondcorp.com/), which is Googles Zero Trust
Security Model.

## Background ##

### What is Mutual TLS? ###

Mutual TLS is a sub-category of [Mutual Authentication](https://en.wikipedia.org/wiki/Mutual_authentication), where the
client and server, or server and server are verifying the identity of one another to ensure that both parties should be
allowed to access the requested information.

### What is this Good For? ###

Creating services that inheritely trust no one unless specifically authorized.  This provides the basis for a zero
trust, multi-factor authentication scheme while also timeboxing access to the requested service in case of compromise or
loss of access keys.

## Configuration ##

### ENV ###

| Parameter       | Description                     | Default    |
| --------        | -----------                     | -------    |
| CONFIG_PATH     | The path to the config file     | config.ini |
| PROTOCOL        | The protocol the server runs as | http       |
| FQDN            | The Fully Qualified Domain Name | localhost  |
| CA_KEY_PASSWORD | The password for the CA Key     |            |

### config.ini ###

| Section          | Field          | Description                                                                   |
| -------          | -----          | -----------                                                                   |
| mtls             | min_lifetime   | Minimum lifetime of a Client Certificate in seconds.                          |
| mtls             | max_lifetime   | Maximum lifetime of a Client Certificate in seconds. 0 means this is disabled |
| ca               | key            | The path to the CA key                                                        |
| ca               | cert           | The path to the CA Certificate                                                |
| ca               | alternate_name | Alternate DNS name that can be comma separated for multiples                  |
| gnupg            | user           | Path to the user GNUPGHOME                                                    |
| gnupg            | admin          | Path to the admin GNUPGHOME                                                   |
| storage          | engine         | The engine type for storage: sqlite3 or postgres                              |
| storage.sqlite3  | db_path        | Path to the sqlite3 database file                                             |
| storage.postgres | database       | Database name                                                                 |
| storage.postgres | user           | Database user                                                                 |
| storage.postgres | password       | Database password                                                             |
| storage.postgres | host           | Database host                                                                 |

## Production ##

### Running From Source ###

1. Download the package

    ```shell
    git clone https://github.com/drGrove/mtls-server
    ```

2. Install Packages

    ```shell
    make setup
    ```

3. Run the server (This requires docker)

    ```shell
    make run-prod
    ```

## Development ##

### Dependencies ###

* make
* pipenv
* docker

### Getting Started ###

1. Install the git hooks, generate base secrets for testing and install dependencies

    ```shell
    make setup-dev
    cp config.ini.example config.ini
    ```

2. Edit the config to have the issuer name and alternate names your service is creating client certificates for.

3. Run the service. This will not have some of the final checkers as those are handled in nginx as nginx is the primary
   test case for this.

    ```shell
    make run
    ```

4. Check the final build. This will allow you to test all configurations end to end and ensure that you're able to hit
   the test endpoint `/test/` with your new client certificate. You should be testing this against
   [mtls-client](https://github.com/drGrove/mtls-client) for integration testing. More details on how your system is
   modified to handle these certificates will be found there.
