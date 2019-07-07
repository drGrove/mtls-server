from . import exceptions
from .postgres import PostgresqlStorageEngine
from .sqlite import SQLiteStorageEngine

class StorageEngine:
    """
    StorageEngine is a factory that returns a concrete engine implementation
    depending on the configuration
    """

    def __new__(cls, config):
        engine = config.get("storage", "engine", fallback=None)
        if engine is None:
            raise exceptions.StorageEngineMissing()
        if engine == "sqlite3":
            return SQLiteStorageEngine(config)
        elif engine == "postgres":
            return PostgresqlStorageEngine(config)
        else:
            raise exceptions.StorageEngineNotSupportedError(engine)
