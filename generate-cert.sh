#!/bin/bash
IP=$1
/usr/bin/openssl req -new -sha256 -key server.key -subj "/C=US/ST=WA/O=Raspberry Pi/CN=${IP}" -extensions SAN -config <(/bin/cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=IP:${IP}")) -out server.cert -days 730 -x509
