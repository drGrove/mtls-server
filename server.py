import os
import sys
from configparser import ConfigParser

from flask import Flask
from flask import request
import json

from cert_processor import CertProcessor
from cert_processor import CertProcessorKeyNotFoundError

__author__ = 'Danny Grove <danny@drgrovell.com>'
VERSION = 'version 0.1'

app = Flask(__name__)
config = ConfigParser()
config.read('config.ini')

def error_respone(msg):
    return json.dumps({
        'error': True,
        'msg': msg
    }), 501


@app.route('/', methods=['POST'])
def create_cert():
    body = request.get_json()
    lifetime = int(body['lifetime'])
    if lifetime < 1:
        error_respone('lifetime must be greater than 1 hour')
    cert_processor = CertProcessor(config)
    csr, user_fingerprint = cert_processor.decrypt(body['csr'])
    if csr is None:
        return error_respone('Could not decrypt csr')
    if user_fingerprint is None:
        return error_respone('Encrypted CSR must be signed')
    csr = cert_processor.get_csr(csr)
    if csr is None:
        return error_respone('Invalid CSR')
    try:
        cert = cert_processor.generate_cert(csr, lifetime)
    except CertProcessorKeyNotFoundError:
        return error_response('Internal Error')
    cert = cert_processor.encrypt(str(cert), user_fingerprint)
    return json.dumps({
        'data': str(cert)
    })


if __name__ == '__main__':
    app.run(port=4000)
