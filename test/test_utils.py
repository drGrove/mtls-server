from pathlib import Path
import logging
import os
import tempfile
import unittest

from mtls_server.utils import create_dir_if_missing
from mtls_server.utils import get_abs_path

logging.disable(logging.CRITICAL)


class TestUtils(unittest.TestCase):
    def test_get_abs_path_from_relative(self):
        cur = Path(os.path.realpath(__file__))
        expected = f"{cur.parent.parent}/config.ini"
        self.assertEqual(get_abs_path("./config.ini"), expected)

    def test_get_abs_path_from_abs(self):
        cur = Path(os.path.realpath(__file__))
        expected = f"{cur.parent.parent}/config.ini"
        self.assertEqual(get_abs_path(expected), expected)

    def test_create_dir_if_missing(self):
        self.TEMPDIR = tempfile.TemporaryDirectory()
        new_dir = f"{self.TEMPDIR.name}/foo/bar/"
        create_dir_if_missing(new_dir)
        self.assertTrue(os.path.isdir(new_dir))
        self.TEMPDIR.cleanup()
