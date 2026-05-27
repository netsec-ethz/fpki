#!/bin/bash

set -e

HOST="articuno"
SRCDIR="cmd/mapserver/user_service"


scp bin/mapserver "${HOST}:~/bin/"
scp "${SRCDIR}/config.json" "${SRCDIR}/mapserver.service" "${SRCDIR}/README.md" "${HOST}:~/fpki-config/"
scp "tests/testdata/servercert.pem" "tests/testdata/serverkey.pem" "${HOST}:~/fpki-config/"

echo "done."
