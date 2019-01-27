#!/usr/bin/env bash
chown -R www-data:www-data /srv/
service nginx start
uwsgi --ini uwsgi.ini
