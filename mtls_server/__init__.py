import os
import sys

from pkg_resources import get_distribution, DistributionNotFound

__author__ = "Danny Grove <danny@drgrovellc.com>"

try:
    __version__ = get_distribution(__name__).version
except DistributionNotFound:
    __version__ = "dev"

# Allows "import mtls_server" and "from mtls_server import <name>".
sys.path.extend([os.path.join(os.path.dirname(__file__), "..")])

from . import cert_processor
from . import handler
from . import server
from . import storage
from . import utils
