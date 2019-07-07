from configparser import ConfigParser
import sys

from .logger import logger
from .server import create_app
from .utils import get_config_from_file


config = None

try:
    import uwsgi  # noqa
    if uwsgi.opt.get("config_data", False):
        config_str = uwsgi.opt["config_data"].decode("utf-8")
        config = ConfigParser()
        config.read_string(config_str)
    app = create_app(config)
except Exception as e:
    logger.critical(e)
    sys.exit(1)
