import base64
import os
import time
import json
from functools import wraps

import gnupg
from flask import request
from flask import g
from flask import current_app

from .utils import error_response
from .utils import time_in_range
from .utils import write_sig_to_file


class SignatureTimestampOutOfBoundsException(Exception):
    pass


class MissingTokenException(Exception):
    pass


class BadSignatureException(Exception):
    pass


def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        allowed_tokens = ['PGP-SIG']
        gpg = gnupg.GPG(gnupghome=current_app.config['GNUPGHOME'])
        gpg.encoding = "utf-8"

        if not request.headers['Authorization']:
            return error_response("authentication required", 401)

        token_type, token = request.headers['Authorization'].split(' ')

        if token_type not in allowed_tokens:
            return error_response("authentication required", 401)

        if token_type == "PGP-SIG":
            data = request.get_data()
            request.input_stream.seek(0)
            b64d_token = base64.b64decode(token)
            sig_path = write_sig_to_file(b64d_token)
            verified = gpg.verify_data(
                sig_path,
                data
            )
            os.remove(sig_path)
            now = time.time()
            if not time_in_range(now-5, now, int(verified.timestamp)):
                return error_response("signature timestamp out of range", 401)

            g.user_fingerprint = verified.pubkey_fingerprint

        return f(*args, **kwargs)

    return wrap
