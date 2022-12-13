#!/bin/bash

# SHA256withRSA  
openssl genrsa -out BoxCertRSA2048.pem 2048   
openssl req -new -key BoxCertRSA2048.pem -out BoxCertRSA2048.csr   
openssl x509 -req -days 1000 -in BoxCertRSA2048.csr -CA RootCA.crt -CAkey RootCA.pem -CAcreateserial -out BoxCertRSA2048.crt 

# SHA256withDSA  
openssl dsaparam -out Boxdsaparam2048.pem 2048 
openssl gendsa -out BoxCertDSA2048.pem Boxdsaparam2048.pem 
openssl req -new -key BoxCertDSA2048.pem -out BoxCertDSA2048.csr   
openssl x509 -req -days 1000 -in BoxCertDSA2048.csr -CA RootCA.crt -CAkey RootCA.pem -CAcreateserial -out BoxCertDSA2048.crt 

# ECDSA, ecspec: secp256r1
openssl ecparam -genkey -name prime256v1 -noout -out tmpECDSA.pem 
openssl pkey -in tmpECDSA.pem -out BoxECDSAsecp256r1.pem
rm tmpECDSA.pem
openssl req -new -key BoxECDSAsecp256r1.pem -out BoxECDSAsecp256r1.csr   
openssl x509 -req -days 1000 -in BoxECDSAsecp256r1.csr -CA RootCA.crt -CAkey RootCA.pem -CAcreateserial -out BoxECDSAsecp256r1.crt 

cat BoxCertRSA2048.crt BoxCertDSA2048.crt BoxECDSAsecp256r1.crt > allBoxCerts.crt  