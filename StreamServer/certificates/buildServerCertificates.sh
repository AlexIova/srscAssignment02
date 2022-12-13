#!/bin/bash

# SHA256withRSA  
openssl genrsa -out ServerCertRSA2048.pem 2048  
openssl req -new -key ServerCertRSA2048.pem -out ServerCertRSA2048.csr  
openssl x509 -req -days 1000 -in ServerCertRSA2048.csr -CA RootCA.crt -CAkey RootCA.pem -CAcreateserial -out ServerCertRSA2048.crt

# SHA256withDSA  
openssl dsaparam -out Serverdsaparam2048.pem 2048
openssl gendsa -out ServerCertDSA2048.pem Serverdsaparam2048.pem
openssl x509 -req -days 1000 -in ServerCertDSA2048.csr -CA RootCA.crt -CAkey RootCA.pem -CAcreateserial -out ServerCertDSA2048.crt

# ECDSA, ecspec: secp256r1
openssl ecparam -genkey -name prime256v1 -out ServerECDSAsecp256r1.pem
openssl req -new -key ServerECDSAsecp256r1.pem -out ServerECDSAsecp256r1.csr  
openssl x509 -req -days 1000 -in ServerECDSAsecp256r1.csr -CA RootCA.crt -CAkey RootCA.pem -CAcreateserial -out ServerECDSAsecp256r1.crt

cat ServerCertRSA2048.crt ServerCertDSA2048.crt ServerECDSAsecp256r1.crt > allServerCerts.crt  