import os
import json

import gnupg
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from flask import Flask
from flask import request
from flask import g

from .auth import admin_required
from .auth import login_required
from .cert_processor import CertProcessor
from .cert_processor import CertProcessorKeyNotFoundError
from .cert_processor import CertProcessorKeyNotFoundError
from .cert_processor import CertProcessorMismatchedPublicKeyError
from .cert_processor import CertProcessorNoPGPKeyFoundError
from .cert_processor import CertProcessorNotAdminUserError
from .config import Config
from .logger import logger
from .sync import Sync
from .utils import PGPKeyNotFoundException
from .utils import PGPTrustException
from .utils import add_and_trust_user
from .utils import create_dir_if_missing
from .utils import error_response
from .utils import get_abs_path
from .utils import has_user

__author__ = "Danny Grove <danny@drgrovellc.com>"

app = None
CONFIG_PATH = os.environ.get(
    "CONFIG_PATH", os.path.join(os.getcwd(), "config.ini")
)


def create_app(config=None):
    app = Flask(__name__)
    app.config['MAX_CONTENT_LENGTH'] = os.environ.get('MAX_CONTENT_LENGTH')

    if config is None:
        Config.init_config(CONFIG_PATH)

    # Set the CWD so that other areas can reference it.
    Config.config.set("mtls", "cwd", os.getcwd())

    user_gpg_path = get_abs_path(
        config.get(
            "gnupg", "user", os.path.join(os.getcwd(), "secrets/gnupg")
        )
    )
    create_dir_if_missing(user_gpg_path)
    user_gpg = gnupg.GPG(gnupghome=user_gpg_path)
    user_gpg.encoding = 'UTF-8'
    app.config.update(user_gpg=user_gpg)
    admin_gpg_path = get_abs_path(
        config.get(
            "gnupg",
            "admin",
            os.path.join(os.getcwd(), "secrets/gnupg_admin"),
        )
    )
    create_dir_if_missing(admin_gpg_path)
    admin_gpg = gnupg.GPG(gnupghome=admin_gpg_path)
    admin_gpg.encoding = 'UTF-8'
    app.config.update(admin_gpg=admin_gpg)

    # Seed the trust stores
    seed = os.environ.get("SEED_ON_INIT", "1")
    if seed == "1":
        logger.debug("Seeding trust store")
        Sync(Config).seed()

    logger.debug("Configuring certificate processor")
    cert_processor = CertProcessor(Config, user_gpg, admin_gpg)

    with open("VERSION", "r") as f:
        version = str(f.readline().strip())

    # This will generate a CA Certificate and Key if one does not exist
    try:
        logger.debug("Getting CA Cert")
        cert_processor.get_ca_cert()
    except CertProcessorKeyNotFoundError:
        # Auto-gen a new key and cert if one is not presented and this is the
        # first call ever made to the handler
        logger.debug("Getting CA Key")
        key = cert_processor.get_ca_key()
        cert_processor.get_ca_cert(key)

    @app.route("/ca", methods=["GET"])
    def get_ca_cert():
        cert = cert_processor.get_ca_cert()
        cert = cert.public_bytes(serialization.Encoding.PEM).decode("UTF-8")
        return (
            json.dumps({"issuer": Config.get("ca", "issuer"), "cert": cert}),
            200,
        )

    @app.route("/crl", methods=["GET"])
    def get_crl():
        crl = cert_processor.get_crl()
        return crl.public_bytes(serialization.Encoding.PEM).decode("UTF-8")

    @app.route("/version", methods=["GET"])
    def get_version():
        return json.dumps({"version": version}), 200


    @app.route("/certs", methods=["GET"])
    def get_certificates():
        return error_response("Not implemented", status_code=501)

    @app.route("/certs", methods=["POST"])
    @login_required
    def create_cert():
        body = request.get_json()
        fingerprint = g.user_fingerprint
        lifetime = int(body.get("lifetime"))
        min_lifetime = Config.get_int("mtls", "min_lifetime", 60)
        max_lifetime = Config.get_int("mtls", "max_lifetime", 0)
        if lifetime < min_lifetime:
            logger.info(
                f"User requested lifetime less than minimum. {lifetime} < {min_lifetime}"
            )
            lifetime = min_lifetime
        if max_lifetime != 0:
            if lifetime > max_lifetime:
                logger.info(
                    f"User requested lifetime greater than maximum. {lifetime} < {max_lifetime}"
                )
                lifetime = max_lifetime
        csr_str = body["csr"]
        csr = cert_processor.get_csr(csr_str)
        if csr is None:
            return error_response("Could not load CSR")
        cert = None
        try:
            logger.info(
                f"create_cert: generating certificate for: {fingerprint}"
            )
            cert = cert_processor.generate_cert(
                csr, lifetime, fingerprint
            )
            logger.info(
                f"create_cert: sending certificate to client for: {fingerprint}"
            )
            return json.dumps({"cert": cert.decode("UTF-8")}), 200
        except CertProcessorKeyNotFoundError:
            logger.critical("Key missing. Service not properly initialized")
            return error_response("Internal Error")
        except CertProcessorMismatchedPublicKeyError:
            logger.error("CSR Public Key does not match found certificate.")
            return error_response("Internal Error")
        except CertProcessorNotAdminUserError:
            logger.error(
                "User {} is not an admin and attempted ".format(fingerprint)
                + "to generate a certificate they are not allowed to generate."
            )
            return error_response("Invalid Request", 403)
        except CertProcessorNoPGPKeyFoundError:
            logger.info("PGP Key not found.")
            return error_response("Unauthorized", 401)
        except Exception as e:
            logger.critical(f"Unhandled Exception: {e}")
            return error_response("Internal Server Error", 500)

    @app.route("/certs/<serial>", methods=["GET"])
    @login_required
    def get_certificate_by_serial():
        return error_response("Not implemented", status_code=501)

    @app.route("/certs/<serial>", methods=["DELETE"])
    @login_required
    def revoke_certificate_by_serial(serial):
        if g.is_admin:
            logger.info(
                f"Admin {g.user_fingerprint} revoking certificate with serial {serial}"
            )
            certs = cert_processor.storage.get_cert(serial)
        else:
            logger.info(
                f"User {g.user_fingerprint} revoking certificate with serial {serial}"
            )
            certs = cert_processor.storage.get_cert(serial, fingerprint=g.user_fingerprint)

        if not len(certs):
            return error_response(f"No certificate", 404)
        for cert in certs:
            cert = x509.load_pem_x509_certificate(
                str(cert).encode("UTF-8"), backend=default_backend()
            )
            cert_processor.revoke_cert(cert.serial_number)
        return json.dumps({"msg": "success"}), 200

    @app.route("/users", methods=["GET"])
    @login_required
    def get_users():
        return error_response("Not implemented", status_code=501)

    @app.route("/users", methods=["POST"])
    @login_required
    @admin_required
    def add_user():
        body = request.get_json()
        logger.debug(body)
        if not body:
            return error_response(f"Could not parse body", 400)
        keyserver = Config.get("gnupg", "keyserver", "keyserver.ubuntu.com")
        fingerprint = body.get('fingerprint', None)
        if not fingerprint:
            return error_response(f"Could not parse body", 400)
        admin = body.get('admin', False)
        if not fingerprint:
            return error_response("Fingerprint missing", 400)
        try:
            if admin:
                admin_exists = has_user(
                    cert_processor.admin_gpg,
                    fingerprint
                )
                if not admin_exists:
                    logger.info(
                        f"Admin {g.user_fingerprint} adding admin user {fingerprint}"
                    )
                    # Add a user to the admin trust store
                    add_and_trust_user(
                        cert_processor.admin_gpg,
                        fingerprint,
                        keyserver
                    )

            user_exists = has_user(cert_processor.user_gpg, fingerprint)
            logger.info(f"Has User {has_user}")

            if not user_exists:
                logger.info(
                    f"Admin {g.user_fingerprint} adding admin user {fingerprint}"
                )
                add_and_trust_user(
                    cert_processor.user_gpg,
                    fingerprint,
                    keyserver,
                )
            return json.dumps({"msg": "success"}), 201
        except PGPKeyNotFoundException:
            return (
                json.dumps(
                    {"msg": "Key not found on keyserver. Could not import"}
                ),
                422,
            )
        except PGPTrustException:
            return (
                json.dumps(
                    {"msg": "Key could not be trusted"}
                ),
                422,
            )


    @app.route("/users/<fingerprint>", methods=["DELETE"])
    @login_required
    @admin_required
    def remove_user_by_fingerprint(fingerprint):
        body = request.get_json()
        admin = body.get('admin', False)
        if admin:
            cert_processor.admin_gpg.delete_keys(fingerprint)

        cert_processor.user_gpg.delete_keys(fingerprint)
        return json.dumps({"msg": "success"}), 200

    return app


def main():
    app = create_app()
    app.run(port=Config.get_int("mtls", "port", 4000))


if __name__ == "__main__":
    main()
