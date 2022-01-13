import os
import json

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from flask import g

from .cert_processor import CertProcessor
from .cert_processor import CertProcessorInvalidSignatureError
from .cert_processor import CertProcessorKeyNotFoundError
from .cert_processor import CertProcessorMismatchedPublicKeyError
from .cert_processor import CertProcessorNoPGPKeyFoundError
from .cert_processor import CertProcessorNotAdminUserError
from .cert_processor import CertProcessorUntrustedSignatureError
from .logger import logger
from .sync import Sync
from .utils import error_response
from .utils import write_sig_to_file


class PGPKeyNotFoundException(Exception):
    pass


class PGPTrustException(Exception):
    pass


class Handler:
    def __init__(self, config):
        # Seed the trust stores
        seed = os.environ.get("SEED_ON_INIT", "1")
        if seed == "1":
            Sync(config).seed()
        self.cert_processor = CertProcessor(config)
        self.config = config

    def create_cert(self, body):
        """Create a certificate."""
        logger.info("Handler.create_cert")
        lifetime = int(body["lifetime"])
        min_lifetime = self.config.get_int("mtls", "min_lifetime", 60)
        max_lifetime = self.config.get_int("mtls", "max_lifetime", 0)
        if lifetime < min_lifetime:
            logger.info(
                f"User requested lifetime less than minimum. {lifetime} < {min_lifetime}"
            )
            lifetime = min_lifetime
        if max_lifetime != 0:
            if lifetime > max_lifetime:
                logger.info(
                    f"User requested lifetime greater than maximum. {lifetime} < {max_lifetime}"
                )
                lifetime = max_lifetime
        csr_str = body["csr"]
        csr = self.cert_processor.get_csr(csr_str)
        if csr is None:
            return error_response("Could not load CSR")
        fingerprint = g.user_fingerprint
        cert = None
        try:
            logger.info(
                f"create_cert: generating certificate for: {fingerprint}"
            )
            cert = self.cert_processor.generate_cert(
                csr, lifetime, fingerprint
            )
            logger.info(
                f"create_cert: sending certificate to client for: {fingerprint}"
            )
            return json.dumps({"cert": cert.decode("UTF-8")}), 200
        except CertProcessorKeyNotFoundError:
            logger.critical("Key missing. Service not properly initialized")
            return error_response("Internal Error")
        except CertProcessorMismatchedPublicKeyError:
            logger.error("CSR Public Key does not match found certificate.")
            return error_response("Internal Error")
        except CertProcessorNotAdminUserError:
            logger.error(
                "User {} is not an admin and attempted ".format(fingerprint)
                + "to generate a certificate they are not allowed to generate."
            )
            return error_response("Invalid Request", 403)
        except CertProcessorNoPGPKeyFoundError:
            logger.info("PGP Key not found.")
            return error_response("Unauthorized", 401)
        except Exception as e:
            logger.critical(f"Unhandled Exception: {e}")
            return error_response("Internal Server Error", 500)

    def revoke_cert(self, body):
        """
        A user should be able to revoke their own certificate. An admin should
        be able to revoke the certificate of any user.

        Args:
            body: A dictionary from the JSON input.

        Returns:
            (json, int): a tuple of the json response and http status code.
        """
        fingerprint = None
        sig_path = write_sig_to_file(body["signature"])
        try:
            fingerprint = self.cert_processor.admin_verify(
                json.dumps(body["query"]).encode("UTF-8"), sig_path
            )
            logger.info(
                f"Admin {fingerprint} revoking certificate with query {json.dumps(body['query'])}"
            )
            os.remove(sig_path)
        except (
            CertProcessorInvalidSignatureError,
            CertProcessorUntrustedSignatureError,
        ):
            try:
                fingerprint = self.cert_processor.verify(
                    json.dumps(body["query"]).encode("UTF-8"), sig_path
                )
                logger.info(
                    "User {userfp} revoking certificate with query {query}".format(
                        userfp=fingerprint, query=json.dumps(body["query"])
                    )
                )
                os.remove(sig_path)
            except (
                CertProcessorInvalidSignatureError,
                CertProcessorUntrustedSignatureError,
            ):
                os.remove(sig_path)
                return error_response("Unauthorized", 403)

        certs = self.cert_processor.storage.get_cert(**body["query"])
        if certs is None:
            return error_response("No Cert to revoke")
        for cert in certs:
            cert = x509.load_pem_x509_certificate(
                str(cert).encode("UTF-8"), backend=default_backend()
            )
            self.cert_processor.revoke_cert(cert.serial_number)
        return json.dumps({"msg": "success"}), 200

    def add_user(self, body, is_admin=False):
        """Add a user or admin."""
        fingerprint = None
        sig_path = write_sig_to_file(body["signature"])
        try:
            fingerprint = self.cert_processor.admin_verify(
                body["fingerprint"].encode("UTF-8"), sig_path
            )
        except (
            CertProcessorInvalidSignatureError,
            CertProcessorUntrustedSignatureError,
        ):
            os.remove(sig_path)
            logger.error(
                "Invalid signature on adding fingerprint: {fp}".format(
                    fp=body["fingerprint"]
                )
            )
            return error_response("Unauthorized", 403)
        # Remove signature file
        os.remove(sig_path)

        fingerprint = body["fingerprint"]

        try:
            if is_admin:
                has_user = self.has_user(
                    self.cert_processor.admin_gpg, fingerprint
                )
                if not has_user:
                    logger.info(
                        f"Admin {fingerprint} adding admin user {body['fingerprint']}"
                    )
                    # Add a user to the admin trust store
                    self.add_and_trust_user(
                        self.cert_processor.admin_gpg, fingerprint
                    )

            has_user = self.has_user(self.cert_processor.user_gpg, fingerprint)

            if not has_user:
                # Add the user to the user trust store
                logger.info(
                    f"Admin {fingerprint} adding admin user {body['fingerprint']}"
                )
                self.add_and_trust_user(
                    self.cert_processor.user_gpg, fingerprint
                )
            return json.dumps({"msg": "success"}), 201
        except PGPKeyNotFoundException:
            return (
                json.dumps(
                    {"msg": "Key not found on keyserver. Could not import"}
                ),
                422,
            )
        except PGPTrustException:
            return (
                json.dumps(
                    {"msg": "Key could not be trusted"}
                ),
                422,
            )

    def has_user(self, gpg, fingerprint):
        keys = gpg.list_keys(keys=fingerprint)
        if len(keys) == 0:
            return False
        return True

    def add_and_trust_user(self, gpg, fingerprint):
        keyserver = self.config.get("gnupg", "keyserver", "keyserver.ubuntu.com")
        logger.info(f"Retrieving key {fingerprint} from {keyserver}")
        result = gpg.recv_keys(
            keyserver,
            fingerprint,
        )
        if result.count is None or result.count == 0:
            raise PGPKeyNotFoundException()

        logger.info(f"Trusting {fingerprint}")
        try:
            result = self.cert_processor.user_gpg.trust_keys(
                [fingerprint], "TRUST_ULTIMATE"
            )
        except ValueError:
            raise PGPTrustException()

    def remove_user(self, body, is_admin=False):
        """Remove a user or admin."""
        fingerprint = None
        sig_path = write_sig_to_file(body["signature"])
        try:
            fingerprint = self.cert_processor.admin_verify(
                body["fingerprint"].encode("UTF-8"), sig_path
            )
            logger.info(
                "Admin {adminfp} adding user {userfp}".format(
                    adminfp=fingerprint, userfp=body["fingerprint"]
                )
            )
        except (
            CertProcessorInvalidSignatureError,
            CertProcessorUntrustedSignatureError,
        ):
            os.remove(sig_path)
            logger.error(
                f"Invalid signature on adding fingerprint: {body['fingerprint']}"
            )
            return error_response("Unauthorized", 403)
        # Remove signature file
        os.remove(sig_path)

        if is_admin:
            # Add a user to the admin trust store
            self.cert_processor.admin_gpg.delete_keys(body["fingerprint"])

        # Add the user to the user trust store
        self.cert_processor.user_gpg.delete_keys(body["fingerprint"])
        return json.dumps({"msg": "success"}), 201
