#!/bin/bash

openssl ecparam -genkey -name prime256v1 -out ./server-certificate-expired.key

cd ..

openssl req -config ./openssl-srv.cnf -new -nodes -days 397 -key ./tls-security-testing/server-certificate-expired.key -out ./tls-security-testing/server-certificate-expired.csr

# Make sure it's not more than 365 days; otherwise it will never be accepted by Apple
openssl ca -config ./openssl-ca.cnf -startdate 20240214120000Z -enddate 20240814120000Z -out ./tls-security-testing/server-certificate-expired.cer -infiles ./tls-security-testing/server-certificate-expired.csr

cd tls-security-testing

echo "" >> ./server-certificate-expired.cer

cat ../secrets/https/ca/ca_cert.cer >> ./server-certificate-expired.cer