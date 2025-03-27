#!/bin/bash

mkdir -p newcerts private certs
touch index.txt
echo 1000 > serial
openssl genpkey -algorithm RSA -out private/ca.key -pkeyopt rsa_keygen_bits:4096
openssl req -new -x509 -key private/ca.key -out certs/ca.crt -days 3650 -config cert_gen.cnf -extensions usr_cert
cat certs/ca.crt private/ca.key > mitmproxy-ca.pem
mkdir -p ~/.mitmproxy
mv mitmproxy-ca.pem ~/.mitmproxy/mitmproxy-ca.pem
