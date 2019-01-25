#!/usr/bin/env bash
chown -R www-data:www-data /srv/
service nginx-debug start
uwsgi --ini uwsgi.ini
