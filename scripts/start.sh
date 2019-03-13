#!/usr/bin/env bash
ENV=${ENV:-production}
if [[ "$ENV" -eq "production" ]]; then
    chown -R www-data:www-data /srv/
fi
uwsgi --ini uwsgi.ini
