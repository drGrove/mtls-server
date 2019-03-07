from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import Encoding


class StorageEngineCertificateConflict(Exception):
    """
    Raise when a StorageEngine implementation is asked to persist a certificate
    with a serial number that already exists or CommonName that is already in
    use by another non-expired/revoked certificate
    """


class SqlStorageEngine:
    """
    A Base SQL Storage Engine implementation.
    """
    def close(self):
        return self.conn.close()


class SQLiteStorageEngine(SqlStorageEngine):
    """
    A StorageEngine implementation that persists data to a SQLite3 database
    """

    def __init__(self, config):
        import sqlite3
        db_path = config.get('storage.sqlite3', 'db_path')
        self.conn = sqlite3.connect(db_path, check_same_thread=False)

    def init_db(self):
        cur = self.conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS certs (
                serial_number text,
                common_name text,
                not_valid_after datetime,
                cert blob,
                revoked boolean
            )
            """)
        self.conn.commit()

    def save_cert(self, cert):
        if self.__conflicting_cert_exists(cert):
            raise StorageEngineCertificateConflict

        common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        common_name = common_name[0].value

        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO certs (
                serial_number,
                common_name,
                not_valid_after,
                cert,
                revoked
            )
            VALUES (?, ?, ?, ?, ?)
            """, [
                str(cert.serial_number),
                common_name,
                cert.not_valid_after,
                cert.public_bytes(Encoding.PEM),
                False
            ])
        self.conn.commit()

    def revoke_cert(self, serial_number):
        cur = self.conn.cursor()
        cur.execute('UPDATE certs SET revoked=1 WHERE serial_number=?',
                    [str(serial_number)])
        self.conn.commit()

    def __conflicting_cert_exists(self, cert):
        common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        common_name = common_name[0].value

        cur = self.conn.cursor()
        cur.execute("""
            SELECT count(*) FROM certs
            WHERE serial_number=?
            OR (
                common_name=?
                AND not_valid_after>=datetime('now')
                AND revoked=0
            )
            """, [str(cert.serial_number), common_name])
        conflicts = cur.fetchone()[0]
        return conflicts > 0


class PostgresqlStorageEngine(SqlStorageEngine):
    """
    A StorageEngine implementation that persists data to a Postgresql database
    """

    def __init__(self, config):
        import psycopg2
        self.conn = psycopg2.connect(
            dbname=config.get('storage.postgres', 'database'),
            user=config.get('storage.postgres', 'user'),
            password=config.get('storage.postgres', 'password'),
            host=config.get('storage.postgres', 'host', fallback='localhost'),
            port=config.get('storage.postgres', 'port', fallback=5432)
        )

    def init_db(self):
        cur = self.conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS certs (
                serial_number text,
                common_name text,
                not_valid_after timestamp,
                cert text,
                revoked boolean
            )
            """)
        self.conn.commit()

    def save_cert(self, cert):
        if self.__conflicting_cert_exists(cert):
            raise StorageEngineCertificateConflict

        common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        common_name = common_name[0].value

        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO certs (
                serial_number,
                common_name,
                not_valid_after,
                cert,
                revoked
            )
            VALUES (%s, %s, %s, %s, %s)
            """, (
                str(cert.serial_number),
                common_name,
                cert.not_valid_after,
                cert.public_bytes(Encoding.PEM),
                False
            ))
        self.conn.commit()

    def revoke_cert(self, serial_number):
        cur = self.conn.cursor()
        cur.execute(
            "UPDATE certs SET revoked=true WHERE serial_number = %s",
            (str(serial_number),)
        )
        self.conn.commit()

    def __conflicting_cert_exists(self, cert):
        common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        common_name = common_name[0].value

        cur = self.conn.cursor()
        cur.execute("""
            SELECT count(*) FROM certs
            WHERE serial_number = %s
            OR (
                common_name = %s
                AND not_valid_after>=NOW()
                AND revoked=false
            )
            """, (str(cert.serial_number), common_name))
        conflicts = cur.fetchone()[0]
        return conflicts > 0


class StorageEngineNotSupportedError(Exception):
    """
    Raise when a StorageEngine implementation cannot be created from the
    provided configuration
    """


class StorageEngine:
    """
    StorageEngine is a factory that returns a concrete engine implementation
    depending on the configuration
    """

    def __new__(cls, config):
        engine = config.get('storage', 'engine')
        if engine == 'sqlite3':
            return SQLiteStorageEngine(config)
        elif engine == 'postgres':
            return PostgresqlStorageEngine(config)
        else:
            raise StorageEngineNotSupportedError(engine)
