#!/usr/bin/env bash
chown -R www-data:www-data /srv/
uwsgi --ini uwsgi.ini
