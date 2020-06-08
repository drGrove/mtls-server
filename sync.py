import os

import gnupg

from logger import logger
from utils import get_config_from_file, import_and_trust


class Sync(object):
    def __init__(self, config=None):
        if config is None:
            config = get_config_from_file("config.ini")
        self.config = config
        user_gnupg_path = config.get("gnupg", "user")
        admin_gnupg_path = config.get("gnupg", "admin")
        if not os.path.isabs(user_gnupg_path):
            user_gnupg_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), user_gnupg_path)
            )
        if not os.path.isabs(admin_gnupg_path):
            admin_gnupg_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), admin_gnupg_path)
            )

        self.user_gpg = gnupg.GPG(gnupghome=user_gnupg_path)
        self.admin_gpg = gnupg.GPG(gnupghome=admin_gnupg_path)
        self.user_gpg.encoding = "utf-8"
        self.admin_gpg.encoding = "utf-8"

    def seed(self):
        """Seeds the User and Admin trust databases."""
        logger.info("Seeding PGP Trust Databases")
        seed_base_dir = self.config.get("mtls", "seed_dir", fallback="/tmp/seeds")
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
