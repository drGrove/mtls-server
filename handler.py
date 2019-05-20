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
from cert_processor import CertProcessorInvalidSignatureError
from cert_processor import CertProcessorKeyNotFoundError
from cert_processor import CertProcessorMismatchedPublicKeyError
from cert_processor import CertProcessorUntrustedSignatureError
from cert_processor import CertProcessorNotAdminUserError
from cert_processor import CertProcessorNoPGPKeyFoundError
from logger import logger
from utils import error_response
from utils import write_sig_to_file
from utils import get_config_from_file


class Handler:
    def __init__(self, config=None):
        if config is None:
            config = get_config_from_file('config.ini')
        self.config = config
        self.cert_processor = CertProcessor(config)
        self.seed()

    def seed(self):
        """Seeds the User and Admin trust databases."""
        logger.info('Seeding PGP Trust Databases')
        seed_base_dir = self.config.get(
            'mtls',
            'seed_dir',
            fallback='/tmp/seeds'
        )
        if os.path.isdir(seed_base_dir):
            for trust in ['user', 'admin']:
                seed_dir = os.path.join(seed_base_dir, trust)
                if os.path.isdir(seed_dir):
                    logger.info('Seeding {} Trust Store'.format(trust))
                    for f in os.listdir(seed_dir):
                        f_path = os.path.join(seed_dir, f)
                        if os.path.isfile(f_path):
                            fingerprint = f.split('.')[0]
                            with open(f_path, 'r') as gpg_data:
                                gpg_data = str(gpg_data.read())
                                if trust == 'admin':
                                    self.import_and_trust(
                                        gpg_data,
                                        self.cert_processor.admin_gpg
                                    )
                                # If we add an admin, they're also a user,
                                # so we can just pull the fingerprint once
                                # and use that for logging. It will only show
                                # it's being 'added' to the admin store, but
                                # that's fine since that assumption is already
                                # made
                                fingerprint = self.import_and_trust(
                                    gpg_data,
                                    self.cert_processor.user_gpg
                                )
                                logger.info(
                                    'Added {fp} to {t} Store'.format(
                                        fp=fingerprint,
                                        t=trust
                                    )
                                )

    def import_and_trust(self, key_data, gpg):
        """Imports a key into a given keyring and trust database as well as
        properly trusting it for use.

        Args:
            key_data (str): The key data in ACSII or binary format.
            gpg (gnupg.GPG): The gpg instance.

        Returns:
            str: The fingerprint of the newly imported and trusted key.
        """
        import_data = gpg.import_keys(
            key_data
        )
        fingerprint = import_data.fingerprints[0]
        gpg.trust_keys(
            [fingerprint],
            'TRUST_ULTIMATE'
        )
        return fingerprint

    def create_cert(self, body):
        """Create a certificate."""
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
            logger.info('Unauthorized: {}'.format(e))
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
        except CertProcessorMismatchedPublicKeyError:
            logger.error(
                'CSR Public Key does not match found certificate.'
            )
            return error_response('Internal Error')
        except CertProcessorNotAdminUserError:
            logger.error(
                'User {} is not an admin and attempted '.format(fingerprint) +
                'to generate a certificate they are not allowed to generate.'
            )
            return error_response('Invalid Request', 403)
        except CertProcessorNoPGPKeyFoundError:
            logger.info('PGP Key not found.')
            return error_response('Unauthorized', 401)

    def revoke_cert(self, body):
        """
        A user should be able to revoke their own certificate. An admin should
        be able to revoke the certificate of any user.

        Args:
            body: A dictionary from the JSON input.

        Returns:
            (json, int): a tuple of the json response and http status code.
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
        """Add a user or admin."""
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
            self.cert_processor.admin_gpg.trust_keys(
                [body['fingerprint']],
                'TRUST_ULTIMATE'
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
        self.cert_processor.user_gpg.trust_keys(
            [body['fingerprint']],
            'TRUST_ULTIMATE'
        )
        return json.dumps({
            'msg': 'success'
        }), 201

    def remove_user(self, body, is_admin=False):
        """Remove a user or admin."""
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
