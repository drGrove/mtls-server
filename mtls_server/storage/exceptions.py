class StorageEngineCertificateConflict(Exception):
    """
    Raise when a StorageEngine implementation is asked to persist a certificate
    with a serial number that already exists or CommonName that is already in
    use by another non-expired/revoked certificate
    """


class StorageEngineMissing(Exception):
    """
    Raise when a StorageEngine type is missing.
    """


class UpdateCertException(Exception):
    """
    Raise when attempting to update a cert and parameters are missing.
    """


class StorageEngineNotSupportedError(Exception):
    """
    Raise when a StorageEngine implementation cannot be created from the
    provided configuration
    """
