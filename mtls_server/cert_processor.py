"""Certificate Processor."""
import datetime
import os
import uuid

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, ExtensionOID
import gnupg

from .key_refresh import KeyRefresh
from .logger import logger
from .storage import StorageEngine
from .storage import StorageEngineCertificateConflict
from .storage import StorageEngineMissing
from .utils import create_dir_if_missing
from .utils import get_abs_path


class CertProcessorKeyNotFoundError(Exception):
    pass


class CertProcessorInvalidSignatureError(Exception):
    pass


class CertProcessorUntrustedSignatureError(Exception):
    pass


class CertProcessorMismatchedPublicKeyError(Exception):
    pass


class CertProcessorNotAdminUserError(Exception):
    pass


class CertProcessorNoPGPKeyFoundError(Exception):
    pass

class CertProcessorUnsupportedCriticalExtensionError(Exception):
    pass


class CertProcessor:
    def __init__(self, config):
        """Cerificate Processor.

        Args:
            config (ConfigParser): a config as configparser.
        """
        user_gnupg_path = get_abs_path(
            config.get(
                "gnupg", "user", os.path.join(os.getcwd(), "secrets/gnupg")
            )
        )
        admin_gnupg_path = get_abs_path(
            config.get(
                "gnupg",
                "admin",
                os.path.join(os.getcwd(), "secrets/gnupg_admin"),
            )
        )

        create_dir_if_missing(user_gnupg_path)
        create_dir_if_missing(admin_gnupg_path)

        self.user_gpg = gnupg.GPG(gnupghome=user_gnupg_path)
        self.admin_gpg = gnupg.GPG(gnupghome=admin_gnupg_path)
        self.user_gpg.encoding = "utf-8"
        self.admin_gpg.encoding = "utf-8"

        # Start Background threads for getting revoke/expiry from Keyserver
        KeyRefresh("user_key_refresh", self.user_gpg, config)
        KeyRefresh("admin_key_refresh", self.admin_gpg, config)

        if config.get("storage", "engine", None) is None:
            raise StorageEngineMissing()

        self.storage = StorageEngine(config)
        self.storage.init_db()
        self.config = config
        self.openssl_format = serialization.PrivateFormat.TraditionalOpenSSL
        self.no_encyption = serialization.NoEncryption()
        self.SERVER_URL = config.get(
            "mtls", "fqdn", os.environ.get("FQDN", "localhost")
        )
        self.PROTOCOL = config.get(
            "mtls", "protocol", os.environ.get("PROTOCOL", "http")
        )

    def verify(self, data, signature):
        """Verifies that the signed data is signed by a trusted key.

        Args:
            data (str): The data to be verified.
            signature (str): The signature file.
        Raises:
            CertProcessorInvalidSignatureError: Signing Key not in trust store.
            CertProcessorUntrustedSignatureError: Signing Key in trust store
            but does not have to correct permissions.
        Returns:
            str: The fingerprint of the signer.
        """
        verified = self.user_gpg.verify_data(signature, data)
        if verified is None:
            logger.error("Invalid signature")
            raise CertProcessorInvalidSignatureError
        if (
            verified.trust_level is not None
            and verified.trust_level < verified.TRUST_FULLY
        ):
            logger.error(
                "User with fingerprint: {} does not have the required trust".format(
                    verified.pubkey_fingerprint
                )
            )
            raise CertProcessorUntrustedSignatureError
        if verified.valid is None or verified.valid is False:
            raise CertProcessorInvalidSignatureError
        return verified.pubkey_fingerprint

    def admin_verify(self, data, signature):
        """Verifies that the signed data is signed by an admin key.

        Args:
            data (str): The data to be verified
            signature (str): The signature file
        Raises:
            CertProcessorInvalidSignatureError: Signing Key not in trust store.
            CertProcessorUntrustedSignatureError: Signing Key in trust store
            but does not have to correct permissions.
        Returns:
            str: The fingerprint of the signer.
        """
        verified = self.admin_gpg.verify_data(signature, data)
        if verified is None:
            raise CertProcessorInvalidSignatureError
        if verified.valid is None or verified.valid is False:
            logger.error(
                "Invalid signature for {}".format(verified.fingerprint)
            )
            raise CertProcessorInvalidSignatureError
        if (
            verified.trust_level is not None
            and verified.trust_level < verified.TRUST_FULLY
        ):
            logger.error(
                "User with fingerprint: {} does not have the required trust".format(
                    verified.pubkey_fingerprint
                )
            )
            raise CertProcessorUntrustedSignatureError
        return verified.pubkey_fingerprint

    def get_csr(self, csr):
        """Given a CSR string, get a cryptography CSR Object.

        Args:
            csr (str): A csr string.
        Returns:
            cryptography.x509.CertificateSigningRequest: A cryptography CSR
            Object if it can be parsed, otherwise None.
        """
        try:
            return x509.load_pem_x509_csr(
                bytes(csr, "utf-8"), default_backend()
            )
        except Exception as e:
            logger.error(e)
            return None

    def get_ca_key(self):
        """Get the CA Key.

        Returns:
            cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey: The
            CAs private key.
        """
        ca_key_path = self.config.get("ca", "key")
        if not os.path.isabs(ca_key_path):
            ca_key_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), ca_key_path)
            )
        try:
            ca_dir = "/".join(ca_key_path.split("/")[:-1])
            if not os.path.isdir(ca_dir):
                os.makedirs(ca_dir)
            with open(ca_key_path, "rb") as key_file:
                if os.environ.get("CA_KEY_PASSWORD"):
                    pw = os.environ.get("CA_KEY_PASSWORD").encode("UTF-8")
                else:
                    pw = None
                ca_key = serialization.load_pem_private_key(
                    key_file.read(), password=pw, backend=default_backend()
                )
                return ca_key
        except (ValueError, FileNotFoundError):
            logger.error("Error opening file: {}".format(ca_key_path))
            logger.info("Generating new root key...")
            key = rsa.generate_private_key(
                public_exponent=65537, key_size=4096, backend=default_backend()
            )

            if os.environ.get("CA_KEY_PASSWORD"):
                encryption_algorithm = serialization.BestAvailableEncryption(
                    os.environ.get("CA_KEY_PASSWORD").encode("UTF-8")
                )
            else:
                encryption_algorithm = self.no_encyption

            key_data = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=self.openssl_format,
                encryption_algorithm=encryption_algorithm,
            )

            with open(ca_key_path, "wb") as f:
                f.write(key_data)

            return key

    def get_ca_cert(self, key=None):
        """Get the CA Certificate.

        Args:
            key (cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey):
                A key in cryptography RSAPrivateKey format.

        Returns:
            cryptography.x509.Certificate: The CA Certificate.
        Returns:
            cryptography.x509.Certificate: CA Certificate
        """
        ca_cert_path = get_abs_path(self.config.get("ca", "cert"))
        # Grab the CA Certificate from filesystem if it exists and return
        if os.path.isfile(ca_cert_path):
            with open(ca_cert_path, "rb") as cert_file:
                ca_cert = x509.load_pem_x509_certificate(
                    cert_file.read(), default_backend()
                )
                return ca_cert

        if key is None:
            raise CertProcessorKeyNotFoundError()

        key_id = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(
                    NameOID.COMMON_NAME, self.config.get("ca", "issuer")
                )
            ]
        )
        now = datetime.datetime.utcnow()
        serial = x509.random_serial_number()
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(key_id, critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier(
                    key_id.digest, [x509.DirectoryName(issuer)], serial
                ),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256(), default_backend())
        )
        with open(ca_cert_path, "wb") as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        return ca_cert

    def is_admin(self, fingerprint):
        """Determine if the fingerprint is associated with with an admin.

        Args:
            fingerprint (str): The users fingerprint.

        Returns:
            bool: Is the user an admin.
        """
        if self.get_gpg_key_by_fingerprint(fingerprint, True) is not None:
            return True
        return False

    def get_gpg_key_by_fingerprint(self, fingerprint, is_admin=False):
        if is_admin:
            keys = self.admin_gpg.list_keys()
        else:
            keys = self.user_gpg.list_keys()
        for key in keys:
            if key["fingerprint"] == fingerprint:
                return key
        return None

    def check_subject_against_key(self, subj, signer_key):
        """Check a subject email against the signing fingerprint.

        The only exception to this is if an admin user is to generate a
        certificate on behalf of someone else. This should be done with extreme
        care, but access will only be allowed for the life of the certificate.

        Args:
            subj (cryptography.x509.Name): An x509 subject.
            signer_key (dict): PGP key details from python-gnupg.

        Returns:
            Wheather the subject email matches a PGP uid for a given
            fingerprint.
        """
        email = subj.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)[0].value
        return any(email in uid for uid in signer_key["uids"])

    def check_san_against_key(self, san, signer_key):
        """Check a SAN email against the signing fingerprint.

        The only exception to this is if an admin user is to generate a
        certificate on behalf of someone else. This should be done with extreme
        care, but access will only be allowed for the life of the certificate.

        Args:
            san (cryptography.x509.SubjectAlternativeName): An x509 SubjectAlternativeName.
            signer_key (dict): PGP key details from python-gnupg.

        Returns:
            Wheather the subject email matches a PGP uid for a given
            fingerprint.
        """
        email = san.value.get_values_for_type(x509.RFC822Name)[0]
        return any(email in uid for uid in signer_key["uids"])

    def get_allowed_subject_name(self, subj, ca_cert, gpg_key, is_admin):
        csr_subject_arr = []
        attr = ca_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        if attr:
            ca_cert_organization = attr[0].value
        else:
            ca_cert_organization = ""
        for attribute in subj:
            attr_oid = attribute.oid
            val = attribute.value

            if attr_oid == NameOID.COMMON_NAME:
                csr_subject_arr.append(attribute)
                continue
            if attr_oid == NameOID.EMAIL_ADDRESS:
                email = subj.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)[0].value
                csr_subject_arr.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
                email_in_key = self.check_subject_against_key(subj, gpg_key)
                if not email_in_key and not is_admin:
                    raise CertProcessorNotAdminUserError()
                continue
            if attr_oid == NameOID.ORGANIZATION_NAME:
                # If the organization provided does not align with the CA, just
                # override with the CA Organization Name. Since we've already proven
                # that the user is allowed to create a Client Certificate for this
                # Organization it isn't a big deal
                if val != ca_cert_organization:
                    # If the CA Certificate does not have an organization, just skip
                    if ca_cert_organization != "":
                        continue
                    attribute = x509.NameAttribute(NameOID.ORGANIZATION_NAME, ca_cert_organization)
                csr_subject_arr.append(attribute)
                continue

            logger.warning(f"Disallowed Name OID {attr_oid} removed from Subject")
        return x509.Name(csr_subject_arr)

    def get_allowed_extensions(self, csr, gpg_key, is_admin):
        extensions = []
        for extension in csr.extensions:
            if extension.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                allowed_entries = [x509.RFC822Name]
                final_entries = []
                for entry in allowed_entries:
                    if entry == x509.RFC822Name:
                        email_in_key = self.check_san_against_key(extension, gpg_key)
                        if not email_in_key and not is_admin:
                            raise CertProcessorNotAdminUserError()
                        final_entries.append(x509.RFC822Name(extension.value.get_values_for_type(x509.RFC822Name)[0]))
                extensions.append((x509.SubjectAlternativeName(final_entries), False))
                continue

            ## Catch All
            if extension.critical == True:
                logger.critical(f"CSR with Critical Extension {extension.oid} found could not be processed.")
                raise CertProcessorUnsupportedCriticalExtensionError()
        return extensions

    def generate_cert(self, csr, lifetime, fingerprint):
        """Generate a Certificate from a CSR.

        Args:
            csr: The CSR object
            lifetime: The lifetime of the certificate in seconds
            fingerprint: The fingerprint of the signer for the CSR.

        Raises:
            CertProcessorNotAdminUserError: When an admin request is made
            without and admin key
            CertProcessorInvalidSignatureError: When an invalid user attempts
            to sign a request for a certificate

        Returns:
            The certificates public bytes
        """
        ca_pkey = self.get_ca_key()
        ca_cert = self.get_ca_cert(ca_pkey)
        now = datetime.datetime.utcnow()
        lifetime_delta = now + datetime.timedelta(seconds=int(lifetime))
        is_admin = self.is_admin(fingerprint)
        logger.info(f"generate_cert: getting gpg key for {fingerprint}")
        user_gpg_key = self.get_gpg_key_by_fingerprint(fingerprint, is_admin)
        if user_gpg_key is None:
            raise CertProcessorNoPGPKeyFoundError()

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(self.get_allowed_subject_name(csr.subject, ca_cert, user_gpg_key, is_admin))
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.public_key(csr.public_key())
        builder = builder.serial_number(uuid.uuid4().int)
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(lifetime_delta)
        for extension in self.get_allowed_extensions(csr, user_gpg_key, is_admin):
            builder = builder.add_extension(extension[0], critical=extension[1])

        crl_dp = x509.DistributionPoint(
            [
                x509.UniformResourceIdentifier(
                    "{protocol}://{server_url}/crl".format(
                        protocol=self.PROTOCOL, server_url=self.SERVER_URL
                    )
                )
            ],
            relative_name=None,
            reasons=None,
            crl_issuer=None,
        )
        builder = builder.add_extension(
            x509.CRLDistributionPoints([crl_dp]), critical=False
        )
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True,
        )

        logger.info(f"generate_cert: Signing certificate for {fingerprint}")
        cert = builder.sign(
            private_key=ca_pkey,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )
        try:
            logger.info(f"generate_cert: saving certificate for {fingerprint}")
            self.storage.save_cert(cert, fingerprint)
        except StorageEngineCertificateConflict:
            logger.info(
                f"generate_cert: updating certificate for {fingerprint}"
            )
            cert = self.update_cert(csr, lifetime, user_gpg_key, is_admin)
        return cert.public_bytes(serialization.Encoding.PEM)

    def update_cert(self, csr, lifetime, user_gpg_key, is_admin):
        """Given a CSR, look it up in the database, update it and present the
        new certificate.

        Args:
            csr (cryptography.x509.CertificateSigningRequest): A CSR.
            lifetime (int): Lifetime in seconds.

        Raises:
            CertProcessorMismatchedPublicKeyError: The public key from the new
            CSR does not match the in database Certificate.

        Returns:
           cryptography.x509.Certificate: A Signed Certificate for a user.
        """
        common_name = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        common_name = common_name[0].value
        bcert = bytes(
            str(self.storage.get_cert(common_name=common_name)[0]), "UTF-8"
        )
        old_cert = x509.load_pem_x509_certificate(
            bcert, backend=default_backend()
        )
        old_cert_pub = (
            old_cert.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("UTF-8")
        )
        csr_pub = (
            csr.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("UTF-8")
        )
        if old_cert_pub != csr_pub:
            raise CertProcessorMismatchedPublicKeyError
        ca_pkey = self.get_ca_key()
        ca_cert = self.get_ca_cert(ca_pkey)
        now = datetime.datetime.utcnow()
        lifetime_delta = now + datetime.timedelta(seconds=int(lifetime))

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(old_cert.subject)

        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.public_key(csr.public_key())
        builder = builder.serial_number(old_cert.serial_number)
        builder = builder.not_valid_before(old_cert.not_valid_before)
        builder = builder.not_valid_after(lifetime_delta)
        for extension in self.get_allowed_extensions(csr, user_gpg_key, is_admin):
            builder = builder.add_extension(extension[0], critical=extension[1])
        crl_dp = x509.DistributionPoint(
            [
                x509.UniformResourceIdentifier(
                    "{protocol}://{server_url}/crl".format(
                        protocol=self.PROTOCOL, server_url=self.SERVER_URL
                    )
                )
            ],
            relative_name=None,
            reasons=None,
            crl_issuer=None,
        )
        builder = builder.add_extension(
            x509.CRLDistributionPoints([crl_dp]), critical=False
        )

        cert = builder.sign(
            private_key=ca_pkey,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )
        self.storage.update_cert(cert=cert, serial_number=cert.serial_number)
        return cert

    def get_crl(self):
        """Generates a Certificate Revocation List.

        Returns:
            A Certificate Revocation List.
        """
        ca_pkey = self.get_ca_key()
        ca_cert = self.get_ca_cert(ca_pkey)
        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca_cert.subject)
            .last_update(datetime.datetime.utcnow())
            .next_update(
                datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
            )
        )
        for cert in self.storage.get_revoked_certs():
            # Convert the string cert into a cryptography cert object
            cert = x509.load_pem_x509_certificate(
                bytes(str(cert), "UTF-8"), backend=default_backend()
            )
            # Add the certificate to the CRL
            crl = crl.add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(cert.serial_number)
                .revocation_date(datetime.datetime.utcnow())
                .build(backend=default_backend())
            )
        # Sign the CRL
        crl = crl.sign(
            private_key=ca_pkey,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )
        return crl

    def revoke_cert(self, serial_number):
        """Given a serial number, revoke a certificate.

        Args:
            serial_number (int): A certificate serial number.
        """
        self.storage.revoke_cert(serial_number)
