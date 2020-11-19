import logging

# Log to the screen
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(
    logging.Formatter(
        '%(asctime)s [pid: %(process)d|threadId: %(thread)d|threadName: %(threadName)s] "%(filename)s" (line: %(lineno)d) | %(levelname)s ' + "%(message)s"
    )
)
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(stream_handler)
