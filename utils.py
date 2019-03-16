import json
import os
import random
import re
import unittest
import uuid

from configparser import ConfigParser
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends import openssl
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import gnupg


def generate_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )


def generate_csr(key, common_name):
    country = 'US'
    state = 'CA'
    locality = 'San Francisco'
    organization_name = 'My Org'
    email = 'test@example.com'
    return x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email)
    ])).sign(key, hashes.SHA256(), default_backend())


def gen_pgp_key(email, password, gpg):
    input_data = gpg.gen_key_input(
        name_email=email,
        passphrase=password
    )
    return gpg.gen_key(input_data)


class User:

    def __init__(self, email, password, key, gpg=None):
        self.gpg = gpg
        self.email = email
        self.password = password
        self.key = key
        self.pgp_key = gen_pgp_key(email, password, gpg)
        self.fingerprint = self.pgp_key.fingerprint
        self.__csrs = []

    @property
    def email(self):
        return self.__email

    @email.setter
    def email(self, email):
        self.__email = email

    @property
    def password(self):
        return self.__password

    @password.setter
    def password(self, password):
        self.__password = password

    @property
    def pgp_key(self):
        return self.__pgp_key

    @pgp_key.setter
    def pgp_key(self, pgp_key):
        self.__pgp_key = pgp_key

    @property
    def csrs(self):
        return self.__csrs

    def gen_csr(self, common_name=None):
        if common_name is None:
            common_name = self.email
        csr = generate_csr(self.key, common_name)
        self.__csrs.append(csr)
        return csr


def gen_passwd():
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    chars += '1234567890'
    chars += '!@#$%^&*()-_+=|?><,.'
    pw = ""
    for c in range(50):
        pw += random.choice(chars)
    if re.search('[0-9]+', pw) is None:
        pw = gen_passwd()
    return pw


def error_response(msg, status_code=501):
    return json.dumps({
        'error': True,
        'msg': msg
    }), status_code


def write_sig_to_file(sig_str):
    """
    Writes a signature to a file. Returns the path to the file

    Args:
        sig_str - Signature String

    Return: path to signature file
    """
    sig_path = '/tmp/{}.sig'.format(uuid.uuid4())
    with open(sig_path, 'wb') as f:
        f.write(sig_str.encode('utf-8'))
    return sig_path


def get_abs_path(path):
    """Gets the absolute path given a path."""
    dir_path = os.path.dirname(os.path.realpath(__file__))
    if not os.path.isabs(path):
        return os.path.abspath(
            os.path.join(
                dir_path,
                path
            )
        )


def get_config_from_file(file_name_or_path):
    config = ConfigParser()
    config_path = get_abs_path(file_name_or_path)
    config.read(config_path)
    return config
