#!/bin/sh
for inet in 4 6
do
    sscg --ca-file=certs/localhost${inet}.srv.ca.pem --cert-file=certs/localhost${inet}.srv.pem --cert-key-file=certs/localhost${inet}.srv.key.pem --cert-key-mode=0644 --hostname="localhost${inet}"
    openssl rsa -in certs/localhost${inet}.srv.key.pem -out certs/localhost${inet}.srv.key.pem -passout file:psk.txt -aes256
    sscg --ca-file=certs/localhost${inet}.clt.ca.pem --cert-file=certs/localhost${inet}.clt.pem --cert-key-file=certs/localhost${inet}.clt.key.pem --cert-key-mode=0644 --hostname="localhost${inet} clt"
    openssl rsa -in certs/localhost${inet}.clt.key.pem -out certs/localhost${inet}.clt.key.pem -passout file:psk.txt -aes256
done
