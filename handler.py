import os
from configparser import ConfigParser
import json

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from cert_processor import CertProcessor
from cert_processor import CertProcessorKeyNotFoundError
from cert_processor import CertProcessorInvalidSignatureError
from cert_processor import CertProcessorUntrustedSignatureError
from logger import logger
from utils import error_response
from utils import write_sig_to_file


class Handler:
    def __init__(self, config=None):
        if config is None:
            config = ConfigParser()
            config_path = os.path.abspath(
                os.path.join(
                    os.path.dirname(__file__),
                    'config.ini'
                )
            )
            config.read(config_path)
        self.config = config
        self.cert_processor = CertProcessor(config)

    def create_cert(self, body):
        lifetime = int(body['lifetime'])
        min_lifetime = int(self.config.get(
            'mtls',
            'min_lifetime',
            fallback=60
        ))
        max_lifetime = int(self.config.get(
            'mtls',
            'max_lifetime',
            fallback=0
        ))
        if lifetime < min_lifetime:
            logger.info(
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
                logger.info(
                    'User requested lifetime greater than maximum. {} < {}'
                    .format(
                        lifetime,
                        max_lifetime
                    )
                )
                error_response('lifetime must be less than {} seconds'.format(
                    max_lifetime
                ))
        csr_str = body['csr']
        csr = self.cert_processor.get_csr(csr_str)
        if csr is None:
            return error_response('Could not load CSR')
        try:
            csr_public_bytes = csr.public_bytes(serialization.Encoding.PEM)
            sig_path = write_sig_to_file(body['signature'])
            fingerprint = self.cert_processor.verify(
                csr_public_bytes,
                sig_path
            )
            os.remove(sig_path)
        except CertProcessorUntrustedSignatureError as e:
            logger.info('Unauthorized: {}'.format(e.msg))
            return error_response('Unauthorized', 403)
        except CertProcessorInvalidSignatureError:
            logger.info('Invalid signature in CSR.')
            return error_response('Invalid signature', 401)
        if csr is None:
            logger.info('Invalid CSR.')
            return error_response('Invalid CSR')
        cert = None
        try:
            cert = self.cert_processor.generate_cert(
                csr,
                lifetime,
                fingerprint
            )
            return json.dumps({
                'cert': cert.decode('UTF-8')
            }), 200
        except CertProcessorKeyNotFoundError:
            logger.critical(
                'Key missing. Service not properly initialized'
            )
            return error_response('Internal Error')

    def revoke_cert(self, body):
        """
        A user should be able to revoke their own certificate. An admin should
        be able to revoke the certificate of any user.
        """
        is_admin = False
        fingerprint = None
        sig_path = write_sig_to_file(body['signature'])
        try:
            fingerprint = self.cert_processor.admin_verify(
                json.dumps(body['query']).encode('UTF-8'),
                sig_path
            )
            is_admin = True
            logger.info(
                'Admin {adminfp} revoking certificate with query {query}'
                .format(
                    adminfp=fingerprint,
                    query=json.dumps(body['query'])
                )
            )
            os.remove(sig_path)
        except (CertProcessorInvalidSignatureError,
                CertProcessorUntrustedSignatureError):
            try:
                fingerprint = self.cert_processor.verify(
                    json.dumps(body['query']).encode('UTF-8'),
                    sig_path
                )
                logger.info(
                    'User {userfp} revoking certificate with query {query}'
                    .format(
                        userfp=fingerprint,
                        query=json.dumps(body['query'])
                    )
                )
                os.remove(sig_path)
            except (CertProcessorInvalidSignatureError,
                    CertProcessorUntrustedSignatureError):
                os.remove(sig_path)
                return error_response('Unauthorized', 403)

        certs = self.cert_processor.storage.get_cert(**body['query'])
        if certs is None:
            return error_response('No Cert to revoke')
        for cert in certs:
            cert = x509.load_pem_x509_certificate(
                str(cert).encode('UTF-8'),
                backend=default_backend()
            )
            self.cert_processor.revoke_cert(cert.serial_number)
        return json.dumps({
            'msg': 'success'
        }), 200

    def add_user(self, body, is_admin=False):
        fingerprint = None
        sig_path = write_sig_to_file(body['signature'])
        try:
            fingerprint = self.cert_processor.admin_verify(
                body['fingerprint'].encode('UTF-8'),
                sig_path
            )
            logger.info(
                'Admin {adminfp} adding user {userfp}'.format(
                    adminfp=fingerprint,
                    userfp=body['fingerprint']
                )
            )
        except (CertProcessorInvalidSignatureError,
                CertProcessorUntrustedSignatureError):
            os.remove(sig_path)
            logger.error(
                    'Invalid signature on adding fingerprint: {fp}'.format(
                        fp=body['fingerprint']
                    )
            )
            return error_response('Unauthorized', 403)
        # Remove signature file
        os.remove(sig_path)

        if is_admin:
            # Add a user to the admin trust store
            self.cert_processor.admin_gpg.recv_keys(
                self.config.get(
                    'gnupg',
                    'keyserver',
                    fallback='keyserver.ubuntu.com'
                ),
                body['fingerprint']
            )

        # Add the user to the user trust store
        self.cert_processor.user_gpg.recv_keys(
            self.config.get(
                'gnupg',
                'keyserver',
                fallback='keyserver.ubuntu.com'
            ),
            body['fingerprint']
        )
        return json.dumps({
            'msg': 'success'
        }), 201

    def remove_user(self, body, is_admin=False):
        fingerprint = None
        sig_path = write_sig_to_file(body['signature'])
        try:
            fingerprint = self.cert_processor.admin_verify(
                body['fingerprint'].encode('UTF-8'),
                sig_path
            )
            logger.info(
                'Admin {adminfp} adding user {userfp}'.format(
                    adminfp=fingerprint,
                    userfp=body['fingerprint']
                )
            )
        except (CertProcessorInvalidSignatureError,
                CertProcessorUntrustedSignatureError):
            os.remove(sig_path)
            logger.error(
                    'Invalid signature on adding fingerprint: {fp}'.format(
                        fp=body['fingerprint']
                    )
            )
            return error_response('Unauthorized', 403)
        # Remove signature file
        os.remove(sig_path)

        if is_admin:
            # Add a user to the admin trust store
            self.cert_processor.admin_gpg.delete_keys(body['fingerprint'])

        # Add the user to the user trust store
        self.cert_processor.user_gpg.delete_keys(body['fingerprint'])
        return json.dumps({
            'msg': 'success'
        }), 201
