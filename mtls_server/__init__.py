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

from .cert_processor import CertProcessor  # noqa
from .cert_processor import CertProcessorInvalidSignatureError  # noqa
from .cert_processor import CertProcessorKeyNotFoundError  # noqa
from .cert_processor import CertProcessorMismatchedPublicKeyError  # noqa
from .cert_processor import CertProcessorNoPGPKeyFoundError  # noqa
from .cert_processor import CertProcessorNotAdminUserError  # noqa
from .cert_processor import CertProcessorUntrustedSignatureError  # noqa
from .key_refresh import KeyRefresh  # noqa
from .server import create_app  # noqa
from .sync import Sync  # noqa
