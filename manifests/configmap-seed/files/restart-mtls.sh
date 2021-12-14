#!/bin/sh

echo "Cleaning GPG home"
rm -r ${GNUPGHOME}/*

echo "HUP uwsgi so it gracefully reloads"
killall -1 uwsgi
