import os

import gnupg

from .logger import logger
from .utils import create_dir_if_missing
from .utils import get_abs_path
from .utils import import_and_trust


class Sync(object):
    def __init__(self, config):
        self.config = config

        user_gnupg_path = get_abs_path(config.get(
            "gnupg",
            "user",
            os.path.join(os.getcwd(), "secrets/gnupg")
        ))
        admin_gnupg_path = get_abs_path(config.get(
            "gnupg",
            "admin",
            os.path.join(os.getcwd(), "secrets/gnupg_admin")
        ))

        create_dir_if_missing(user_gnupg_path)
        create_dir_if_missing(admin_gnupg_path)

        self.user_gpg = gnupg.GPG(gnupghome=user_gnupg_path)
        self.admin_gpg = gnupg.GPG(gnupghome=admin_gnupg_path)
        self.user_gpg.encoding = "utf-8"
        self.admin_gpg.encoding = "utf-8"

    def seed(self):
        """Seeds the User and Admin trust databases."""
        logger.info("Seeding PGP Trust Databases")
        seed_base_dir = self.config.get("mtls", "seed_dir", "/tmp/seeds")
        if os.path.isdir(seed_base_dir):
            for trust in ["user", "admin"]:
                seed_dir = os.path.join(seed_base_dir, trust)
                if os.path.isdir(seed_dir):
                    logger.info("Seeding {} Trust Store".format(trust))
                    for f in os.listdir(seed_dir):
                        f_path = os.path.join(seed_dir, f)
                        if os.path.isfile(f_path):
                            fingerprint = f.split(".")[0]
                            with open(f_path, "r") as gpg_data:
                                gpg_data = str(gpg_data.read())
                                if trust == "admin":
                                    import_and_trust(
                                        gpg_data, self.admin_gpg
                                    )
                                # If we add an admin, they're also a user,
                                # so we can just pull the fingerprint once
                                # and use that for logging. It will only show
                                # it's being 'added' to the admin store, but
                                # that's fine since that assumption is already
                                # made
                                fingerprint = import_and_trust(
                                    gpg_data, self.user_gpg
                                )
                                logger.info(
                                    "Added {fp} to {t} Store".format(
                                        fp=fingerprint, t=trust
                                    )
                                )
        logger.info("Completed seeding of Trust Databases")
