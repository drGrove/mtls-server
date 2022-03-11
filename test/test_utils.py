from pathlib import Path
import logging
import os
import tempfile
import time
import unittest

from mtls_server.utils import create_dir_if_missing
from mtls_server.utils import get_abs_path
from mtls_server.utils import time_in_range

logging.disable(logging.CRITICAL)
CLEANUP = os.environ.get('CLEANUP', '1')


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
        if CLEANUP == '1':
            self.TEMPDIR.cleanup()

    def test_time_in_range(self):
        self.assertTrue(time_in_range(1,5,2))
        self.assertTrue(time_in_range(time.time()-5, time.time()+5, time.time()))
        self.assertFalse(time_in_range(time.time()+5, time.time()-5, time.time()))
