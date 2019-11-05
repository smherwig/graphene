#!/bin/bash

# I typically use 'root' as the CN for the root.crt, and 'proc' as
# as the CN for the proc.crt.  I don't provide an e-mail address.

printf "[+] CREATE ROOT KEY\n"
openssl genrsa -out root.key 4096

printf "[+] CREATE SELF-SIGNED ROOT CERTIFICATE\n"
openssl req -x509 -new -nodes -key root.key -sha256 -days 1024 -out root.crt

printf "[+] CREATE PROCESS KEY\n"
openssl genrsa -out proc.key 2048

printf "[+] CREATE PROCESS CERTIFICATE SIGINING REQUEST\n"
openssl req -new -key proc.key -out proc.csr

printf "[+] CREATE PROCESS SIGNED CERTIFICATE\n"
openssl x509 -req -in proc.csr -CA root.crt -CAkey root.key \
    -CAcreateserial -out proc.crt -days 500 -sha256
