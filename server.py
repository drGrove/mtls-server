from configparser import ConfigParser
import json

from cryptography.hazmat.primitives import serialization
from flask import Flask
from flask import request

from cert_processor import CertProcessor
from cert_processor import CertProcessorKeyNotFoundError
from cert_processor import CertProcessorInvalidSignatureError
from cert_processor import CertProcessorUntrustedSignatureError
from handler import Handler
from logger import logger

__author__ = 'Danny Grove <danny@drgrovellc.com>'
VERSION = 'version 0.5'

app = Flask(__name__)


@app.route('/', methods=['POST'])
def main_handler():
    body = request.get_json()
    if body['type'] == "CREATE_CERTIFICATE":
        return handler.create_cert(body)
    if body['type'] == "REVOKE_CERTIFICATE":
        return handler.revoke_cert(body)


@app.route('/ca', methods=['GET'])
def get_ca_cert():
    cert = handler.cert_processor.get_ca_cert()
    return json.dumps({
        'issuer': handler.config.get('ca', 'issuer'),
        'cert': cert.public_bytes(serialization.Encoding.PEM).decode('UTF-8')
    }), 200


@app.route('/crl', methods=['GET'])
def get_crl():
    crl = handler.cert_processor.get_crl()
    return crl.public_bytes(serialization.Encoding.PEM).decode('UTF-8')


if __name__ == '__main__':
    # Prior to initializing the handler ensure that a CA certificate exits
    # otherwise create one so it can be used across endpoints
    handler = Handler()
    try:
        cert = handler.cert_processor.get_ca_cert()
    except CertProcessorKeyNotFoundError:
        # Auto-gen a new key and cert if one is not presented and this is the
        # first call ever made to the handler
        key = handler.cert_processor.get_ca_key()
        cert = handler.cert_processor.get_ca_cert(key)
    app.run(port=handler.config.get('mtls', 'port', fallback=4000))
