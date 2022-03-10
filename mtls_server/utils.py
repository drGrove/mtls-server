import json
import os
import random
import re
import uuid

from configparser import ConfigParser
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .logger import logger


class PGPKeyNotFoundException(Exception):
    pass


class PGPTrustException(Exception):
    pass


def generate_key(key_size=4096):
    return rsa.generate_private_key(
        public_exponent=65537, key_size=key_size, backend=default_backend()
    )


def generate_csr(key, common_name, email=None):
    organization_name = "My Org"
    if email is None:
        email = "test@example.com"
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(
                        NameOID.ORGANIZATION_NAME, organization_name
                    ),
                    x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                    x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
                ]
            )
        )
        .sign(key, hashes.SHA256(), default_backend())
    )


def generate_csr_with_san(key, common_name, email=None):
    organization_name = "My Org"
    if email is None:
        email = "test@example.com"

    subject_name_attributes = [
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ]

    san_attributes = [
        x509.RFC822Name(email)
    ]

    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(x509.Name(subject_name_attributes))
    builder = builder.add_extension(x509.SubjectAlternativeName(san_attributes), False)
    request = builder.sign(key, hashes.SHA256(), default_backend())
    return request


def gen_pgp_key(email, password, gpg, key_size=1024):
    input_data = gpg.gen_key_input(
        name_email=email, passphrase=password, key_length=key_size
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

    def gen_csr(self, common_name=None, email=None, with_san=False):
        if common_name is None:
            common_name = self.email
        if email is None:
            email = self.email
        if with_san:
            csr = generate_csr_with_san(self.key, common_name, email)
        else:
            csr = generate_csr(self.key, common_name, email)
        self.__csrs.append(csr)
        return csr



def gen_passwd():
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    chars += "1234567890"
    chars += "!@#$%^&*()-_+=|?><,."
    pw = ""
    for c in range(50):
        pw += random.choice(chars)
    if re.search("[0-9]+", pw) is None:
        pw = gen_passwd()
    return pw


def error_response(msg, status_code=501):
    return json.dumps({"error": True, "msg": msg}), status_code


def write_sig_to_file(sig):
    """
    Writes a signature to a file. Returns the path to the file

    Args:
        sig_str - Signature String

    Return: path to signature file
    """
    sig_path = "/tmp/{}.sig".format(uuid.uuid4())
    with open(sig_path, "wb") as f:
        f.write(sig)
    return sig_path


def get_abs_path(path):
    """Gets the absolute path given a path."""
    if os.path.isabs(path):
        return path

    return os.path.abspath(os.path.join(os.getcwd(), path))


def get_config_from_file(file_name_or_path):
    config = ConfigParser()
    config_path = get_abs_path(file_name_or_path)
    config.read(config_path)
    return config


def import_and_trust(key_data, gpg):
    """Imports a key into a given keyring and trust database as well as
    properly trusting it for use.

    Args:
        key_data (str): The key data in ACSII or binary format.
        gpg (gnupg.GPG): The gpg instance.

    Returns:
        str: The fingerprint of the newly imported and trusted key.
    """
    import_data = gpg.import_keys(key_data)
    fingerprint = import_data.fingerprints[0]
    gpg.trust_keys([fingerprint], "TRUST_ULTIMATE")
    return fingerprint


def create_dir_if_missing(path):
    if not os.path.isdir(path):
        os.makedirs(path)

def time_in_range(start: float, end: float, t: float) -> bool:
    """Return true if t is in the range [start,end]"""
    if start <= end:
        return start <= t <= end
    return False

def has_user(gpg, fingerprint):
    keys = gpg.list_keys(keys=fingerprint)
    return len(keys) != 0

def add_and_trust_user(gpg, fingerprint, keyserver="keyserver.ubuntu.com"):
    logger.info(f"Retrieving key {fingerprint} from {keyserver}")
    result = gpg.recv_keys(
        keyserver,
        fingerprint,
    )
    if result.count is None or result.count == 0:
        raise PGPKeyNotFoundException()

    logger.info(f"Trusting {fingerprint}")
    try:
        result = gpg.trust_keys(
            [fingerprint], "TRUST_ULTIMATE"
        )
    except ValueError:
        raise PGPTrustException()
