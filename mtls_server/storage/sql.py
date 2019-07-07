class SqlStorageEngine:
    """
    A Base SQL Storage Engine implementation.
    """

    def close(self):
        return self.conn.close()
