from configparser import ConfigParser
import os
import json

from cryptography.hazmat.primitives import serialization
from flask import Flask
from flask import request

from . import __version__
from .cert_processor import CertProcessor
from .cert_processor import CertProcessorInvalidSignatureError
from .cert_processor import CertProcessorKeyNotFoundError
from .cert_processor import CertProcessorUntrustedSignatureError
from .handler import Handler
from .logger import logger
from .utils import get_config_from_file


app = None
handler = None


def create_app(config=None):
    app = Flask(__name__)
    handler = Handler(config)

    # This will generate a CA Certificate and Key if one does not exist
    try:
        cert = handler.cert_processor.get_ca_cert()
    except CertProcessorKeyNotFoundError:
        # Auto-gen a new key and cert if one is not presented and this is the
        # first call ever made to the handler
        key = handler.cert_processor.get_ca_key()
        cert = handler.cert_processor.get_ca_cert(key)

    @app.route("/", methods=["POST"])
    def create_handler():
        body = request.get_json()
        if body["type"] == "CERTIFICATE":
            return handler.create_cert(body)
        if body["type"] == "USER":
            return handler.add_user(body)
        if body["type"] == "ADMIN":
            return handler.add_user(body, is_admin=True)

    @app.route("/", methods=["DELETE"])
    def delete_handler():
        body = request.get_json()
        if body["type"] == "CERTIFICATE":
            return handler.revoke_cert(body)
        if body["type"] == "USER":
            return handler.remove_user(body)
        if body["type"] == "ADMIN":
            return handler.remove_user(body, is_admin=True)

    @app.route("/ca", methods=["GET"])
    def get_ca_cert():
        cert = handler.cert_processor.get_ca_cert()
        cert = cert.public_bytes(serialization.Encoding.PEM).decode("UTF-8")
        return (
            json.dumps({"issuer": handler.config.get("ca", "issuer"), "cert": cert}),
            200,
        )

    @app.route("/crl", methods=["GET"])
    def get_crl():
        crl = handler.cert_processor.get_crl()
        return crl.public_bytes(serialization.Encoding.PEM).decode("UTF-8")

    @app.route("/version", methods=["GET"])
    def get_version():
        return json.dumps({"version": __version__}), 200

    return app


if __name__ == "__main__":
    config_path = os.getenv("CONFIG_PATH", None)
    if config_path:
        config = get_config_from_file(config_path)
    else:
        config = get_config_from_file("../config.ini")
    app = create_app(config)
    app.run(port=config.get("mtls", "port", fallback=4000))
