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

from .cert_processor import CertProcessor
from .cert_processor import CertProcessorInvalidSignatureError
from .cert_processor import CertProcessorKeyNotFoundError
from .cert_processor import CertProcessorMismatchedPublicKeyError
from .cert_processor import CertProcessorNoPGPKeyFoundError
from .cert_processor import CertProcessorNotAdminUserError
from .cert_processor import CertProcessorUntrustedSignatureError
from .key_refresh import KeyRefresh
from .server import create_app
from .sync import Sync
