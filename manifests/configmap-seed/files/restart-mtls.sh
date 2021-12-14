#!/bin/sh

echo "Cleaning GPG home"
rm -r ${GNUPGHOME}/*

echo "Restarting mtls process in main container"
killall uwsgi
