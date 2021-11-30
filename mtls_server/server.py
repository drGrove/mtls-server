from mtls_server.middleware.json_parser import json_parser_middlware
import os
import json

import gnupg
from cryptography.hazmat.primitives import serialization
from flask import Flask
from flask import request
from flask import g

from .auth import login_required
from .cert_processor import CertProcessorKeyNotFoundError
from .config import Config
from .handler import Handler
from .logger import logger
from .utils import create_dir_if_missing, get_abs_path

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

    gnupg_path = get_abs_path(
        config.get(
            "gnupg", "user", os.path.join(os.getcwd(), "secrets/gnupg")
        )
    )
    create_dir_if_missing(gnupg_path)
    app.config['GNUPGHOME'] = gnupg_path
    # admin_gnupg_path = get_abs_path(
    #     config.get(
    #         "gnupg",
    #         "admin",
    #         os.path.join(os.getcwd(), "secrets/gnupg_admin"),
    #     )
    # )

    # create_dir_if_missing(admin_gnupg_path)

    # self.admin_gpg = gnupg.GPG(gnupghome=admin_gnupg_path)

    handler = Handler(Config)

    with open("VERSION", "r") as f:
        version = str(f.readline().strip())

    # This will generate a CA Certificate and Key if one does not exist
    try:
        handler.cert_processor.get_ca_cert()
    except CertProcessorKeyNotFoundError:
        # Auto-gen a new key and cert if one is not presented and this is the
        # first call ever made to the handler
        key = handler.cert_processor.get_ca_key()
        handler.cert_processor.get_ca_cert(key)


    @app.route("/ca", methods=["GET"])
    def get_ca_cert():
        cert = handler.cert_processor.get_ca_cert()
        cert = cert.public_bytes(serialization.Encoding.PEM).decode("UTF-8")
        return (
            json.dumps({"issuer": Config.get("ca", "issuer"), "cert": cert}),
            200,
        )

    @app.route("/crl", methods=["GET"])
    def get_crl():
        crl = handler.cert_processor.get_crl()
        return crl.public_bytes(serialization.Encoding.PEM).decode("UTF-8")

    @app.route("/version", methods=["GET"])
    def get_version():
        return json.dumps({"version": version}), 200

    # app.wsgi_app = auth_middleware(app.wsgi_app, gpg)

    @app.route("/certs", methods=["GET"])
    def get_certificates():
        pass

    @app.route("/certs", methods=["POST"])
    @login_required
    def create_cert():
        body = request.get_json()
        return handler.create_cert(body)

    @app.route("/certs/<serial>", methods=["GET"])
    def get_certificate_by_serial():
        pass

    @app.route("/certs/<serial>", methods=["DELETE"])
    def delete_certificate_by_serial():
        body = request.get_json()
        return handler.revoke_cert(body)

    @app.route("/", methods=["POST"])
    def create_handler():
        body = request.get_json()
        if body["type"] == "USER":
            return handler.add_user(body)
        if body["type"] == "ADMIN":
            return handler.add_user(body, is_admin=True)

    @app.route("/", methods=["DELETE"])
    def delete_handler():
        body = request.get_json()
        if body["type"] == "USER":
            return handler.remove_user(body)
        if body["type"] == "ADMIN":
            return handler.remove_user(body, is_admin=True)


    return app


def main():
    app = create_app()
    app.run(port=Config.get_int("mtls", "port", 4000))


if __name__ == "__main__":
    main()
