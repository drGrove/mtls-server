import logging
import os
import sys
import uuid
from configparser import ConfigParser

from cryptography.hazmat.primitives import serialization
from flask import Flask
from flask import request
import json

from cert_processor import CertProcessor
from cert_processor import CertProcessorKeyNotFoundError
from cert_processor import CertProcessorInvalidSignatureError

__author__ = 'Danny Grove <danny@drgrovell.com>'
VERSION = 'version 0.1'

app = Flask(__name__)
config = ConfigParser()
config_path = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        'config.ini'
    )
)
config.read(config_path)
cert_processor = CertProcessor(config)


def error_response(msg, status_code=501):
    return json.dumps({
        'error': True,
        'msg': msg
    }), status_code


@app.route('/', methods=['POST'])
def create_cert():
    body = request.get_json()
    lifetime = int(body['lifetime'])
    min_lifetime = int(config.get('mtls', 'min_lifetime', fallback=60))
    max_lifetime = int(config.get('mtls', 'max_lifetime', fallback=0))
    if lifetime < min_lifetime:
        logging.info(
            'User requested lifetime less than minimum. {} < {}'.format(
                lifetime,
                min_lifetime
            )
        )
        error_response('lifetime must be greater than {} seconds'.format(
            min_lifetime
        ))
    if max_lifetime != 0:
        if lifetime > max_lifetime:
            logging.info(
                'User requested lifetime greater than maximum. {} < {}'.format(
                    lifetime,
                    max_lifetime
                )
            )
            error_response('lifetime must be less than {} seconds'.format(
                max_lifetime
            ))
    csr_str = body['csr']
    csr = cert_processor.get_csr(csr_str)
    if csr is None:
        return error_response('Could not load CSR')
    try:
        csr_public_bytes = csr.public_bytes(serialization.Encoding.PEM)
        sig_path = '/tmp/{}.asc'.format(uuid.uuid4())
        with open(sig_path, 'wb') as f:
            f.write(bytes(body['signature'], 'utf-8'))
        cert_processor.verify(csr_public_bytes,
                              sig_path)
        os.remove(sig_path)
    except CertProcessorInvalidSignatureError:
        logging.info('Invalid signature in CSR.')
        return error_response('Invalid signature', 401)
    if csr is None:
        logging.info('Invalid CSR.')
        return error_response('Invalid CSR')
    cert = None
    try:
        cert = cert_processor.generate_cert(csr, lifetime)
        return json.dumps({
            'cert': cert.decode('utf-8')
        })
    except CertProcessorKeyNotFoundError:
        logging.critical(
            'Key missing. Service not properly initialized'
        )
        return error_response('Internal Error')


@app.route('/ca', methods=['GET'])
def get_ca_cert():
    try:
        cert = cert_processor.get_ca_cert()
    except CertProcessorKeyNotFoundError:
        # Auto-gen a new key and cert if one is not presented and this is the
        # first call ever made to the server
        key = cert_processor.get_ca_key()
        cert = cert_processor.get_ca_cert(key)
    return json.dumps({
        'issuer': config.get('ca', 'issuer'),
        'cert': cert.public_bytes(serialization.Encoding.PEM).decode('UTF-8')
    })


if __name__ == '__main__':
    app.run(port=config.get('mtls', 'port', fallback=4000))
