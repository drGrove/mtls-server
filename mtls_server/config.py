import os
from configparser import ConfigParser

from .utils import get_abs_path


class Config:
    config = ConfigParser()

    BOOLEAN_STATES = {
        '1': True,
        'yes': True,
        'true': True,
        'on': True,
        '0': False,
        'no': False,
        'false': False,
        'off': False
    }

    @staticmethod
    def init_config(filepath=None, config=None):
        if config:
            Config.config = config
            return

        filepath = get_abs_path(filepath)
        if os.path.exists(filepath):
            Config.config.read(filepath)

    @staticmethod
    def get(section, option, default_value=""):
        if Config.config.has_option(section, option):
            return Config.config.get(section, option, fallback=default_value)
        return os.environ.get(f"{section.upper()}_{option.upper()}", default_value)

    @staticmethod
    def get_int(section, option, default_value):
        if Config.config.has_option(section, option):
            return Config.config.getint(section, option, fallback=default_value)
        return Config._get_conv_env(section, option, int, default_value)

    @staticmethod
    def get_float(section, option, default_value):
        if Config.config.has_option(section, option):
            return Config.config.getfloat(section, option, fallback=default_value)
        return Config._get_conv_env(section, option, float, default_value)

    @staticmethod
    def get_boolean(section, option, default_value):
        if Config.config.has_option(section, option):
            return Config.config.getboolean(section, option, fallback=default_value)
        return Config._get_conv_env(section, option, Config._convert_to_boolean, default_value)

    @staticmethod
    def _get_conv_env(section, option, conv, default_value):
        return conv(os.environ.get(
            '_'.join([section.upper(), option.upper()]), default_value
        ))

    @staticmethod
    def _convert_to_boolean(value):
        if value.lower() not in Config.BOOLEAN_STATES:
            raise ValueError(f'Not a boolean: {value}')
        return Config.BOOLEAN_STATES[value.lower()]
