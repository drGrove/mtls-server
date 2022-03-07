import base64
import os
import time
import pprint
import json
from functools import wraps

from flask import request
from flask import g
from flask import current_app

from .logger import logger
from .utils import error_response
from .utils import time_in_range
from .utils import write_sig_to_file


pp = pprint.PrettyPrinter(indent=4)


class SignatureTimestampOutOfBoundsException(Exception):
    pass


class MissingTokenException(Exception):
    pass


class BadSignatureException(Exception):
    pass


def legacy_verify(data, sig):
    sig_path = write_sig_to_file(sig)
    g.is_admin = False

    verified = current_app.config['admin_gpg'].verify_data(
        sig_path,
        data
    )
    if verified.trust_level is not None and verified.trust_level >= verified.TRUST_ULTIMATE:
        logger.debug(f"authenticated user {verified.pubkey_fingerprint} is admin")
        g.is_admin = True

    if not g.is_admin:
        verified = current_app.config['user_gpg'].verify_data(
            sig_path,
            data
        )

    os.remove(sig_path)

    if verified.trust_level is None:
        return error_response(f"unauthorized: {verified.trust_text} {verified.fingerprint} {verified.status}", 401)

    now = time.time()
    # Time in seconds that signed messages will be accepted once signed.
    sig_auth_time_range = int(os.environ.get('SIG_AUTH_TIME_RANGE', '5'))
    if not time_in_range(now-sig_auth_time_range, now, int(verified.timestamp)):
        return error_response("signature timestamp out of range", 401)

    g.user_fingerprint = verified.pubkey_fingerprint
    return None

def login_required(f):
    @wraps(f)
    def login_required_wrap(*args, **kwargs):
        allowed_tokens = ['PGP-SIG']
        g.is_admin = False

        if not (authorization_header := request.headers['Authorization']):
            return error_response("authentication required", 401)

        try:
            token_type, token = authorization_header.split(' ')
        except Exception as e:
            logger.warning(e)
            return error_response("could not validate authentication", 500)

        if token_type not in allowed_tokens:
            return error_response("authentication required", 401)

        if token_type == "PGP-SIG":
            if request.content_length:
                g.data = data = request.get_data()

                try:
                    g.json = json.loads(g.data)
                except Exception:
                    return error_response("Could not parse body, expected JSON", 400)
            else:
                g.data = data = "NOCONTENT".encode('UTF-8')
                g.json = {}

            b64d_token = base64.b64decode(token)
            sig_path = write_sig_to_file(b64d_token)

            verified = current_app.config['admin_gpg'].verify_data(
                sig_path,
                data
            )
            if verified.trust_level is not None and verified.trust_level >= verified.TRUST_ULTIMATE:
                logger.debug(f"authenticated user {verified.pubkey_fingerprint} is admin")
                g.is_admin = True

            if not g.is_admin:
                verified = current_app.config['user_gpg'].verify_data(
                    sig_path,
                    data
                )

            os.remove(sig_path)

            if verified.trust_level is None:
                return error_response("unauthorized", 401)

            now = time.time()
            # Time in seconds that signed messages will be accepted once signed.
            sig_auth_time_range = int(os.environ.get('SIG_AUTH_TIME_RANGE', '5'))
            if not time_in_range(now-sig_auth_time_range, now, int(verified.timestamp)):
                return error_response("signature timestamp out of range", 401)

            g.user_fingerprint = verified.pubkey_fingerprint

        return f(*args, **kwargs)
    return login_required_wrap


def admin_required(f):
    @wraps(f)
    def admin_wrap(*args, **kwargs):
        logger.info(f"Checking if user is admin... {g.is_admin}")
        if not g.is_admin:
            return error_response("insufficient permissions", 403)

        return f(*args, **kwargs)
    return admin_wrap
