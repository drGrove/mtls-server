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


def error_response(msg, status_code=501):
    return json.dumps({
        'error': True,
        'msg': msg
    }), status_code


@app.route('/', methods=['POST'])
def create_cert():
    body = request.get_json()
    lifetime = int(body['lifetime'])
    if lifetime < 1:
        error_response('lifetime must be greater than 1 hour')
    cert_processor = CertProcessor(config)
    csr_str = body['csr']
    csr = cert_processor.get_csr(csr_str)
    if csr is None:
        return error_response('Could not load CSR')
    try:
        csr_public_bytes = csr.public_bytes(serialization.Encoding.PEM)
        path = '/tmp/{}.asc'.format(uuid.uuid4())
        with open(path, 'wb') as f:
            f.write(bytes(body['signature'], 'utf-8'))
        cert_processor.verify(csr_public_bytes,
                              path)
        os.remove(path)
    except CertProcessorInvalidSignatureError:
        return error_response('Invalid signature', 401)
    if csr is None:
        return error_response('Invalid CSR')
    cert = None
    try:
        cert = cert_processor.generate_cert(csr, lifetime)
        return json.dumps({
            'data': cert.decode('utf-8')
        })
    except CertProcessorKeyNotFoundError:
        return error_response('Internal Error')


if __name__ == '__main__':
    app.run(port=4000)
