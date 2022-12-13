# srscAssignment02

### MAC key
Keystore generated with: `keytool -genseckey -alias mackey -keyalg hmacSHA1 -keysize 128 -keystore mykeystore.jceks -storetype jceks`  
Password: `password`  
Then converted into PKCS12 format: `keytool -importkeystore -srckeystore mykeystore.jceks -destkeystore mykeystore.pkcs12 -deststoretype pkcs12`  

## Commands
### Box
Compile:  
`javac -cp "../bcprov-jdk18on-172.jar:../bcprov-ext-jdk18on-172.jar:." *.java`  
Run:  
`java -cp "../bcprov-jdk18on-172.jar:../bcprov-ext-jdk18on-172.jar:." Box ciao localhost 6789`  

### StreamServer
Compile:  
`javac -cp "../bcprov-jdk18on-172.jar:../bcprov-ext-jdk18on-172.jar:." *.java`  
Run:  
`java -cp "../bcprov-jdk18on-172.jar:../bcprov-ext-jdk18on-172.jar:." StreamServer 6789`  


## Creation certificate

### Box
`openssl genrsa -out RootCA.pem 4096`  
`openssl req -new -x509 -days 1500 -key RootCA.pem -out RootCA.crt`

SHA256withRSA  
`openssl genrsa -out BoxCertRSA2048.pem 2048`  
`openssl req -new -key BoxCertRSA2048.pem -out BoxCertRSA2048.csr`  
`openssl x509 -req -days 1000 -in BoxCertRSA2048.csr -CA RootCA.crt -CAkey RootCA.pem -CAcreateserial -out BoxCertRSA2048.crt`

SHA256withDSA  
`openssl dsaparam -out Boxdsaparam2048.pem 2048`
`openssl gendsa -out BoxCertDSA2048.pem Boxdsaparam2048.pem`
`openssl req -new -key BoxCertDSA2048.pem -out BoxCertDSA2048.csr`  
`openssl x509 -req -days 1000 -in BoxCertDSA2048.csr -CA RootCA.crt -CAkey RootCA.pem -CAcreateserial -out BoxCertDSA2048.crt`

ECDSA, ecspec: secp256r1
`openssl ecparam -genkey -name prime256v1 -out BoxECDSAsecp256r1.pem`
`openssl req -new -key BoxECDSAsecp256r1.pem -out BoxECDSAsecp256r1.csr`  
`openssl x509 -req -days 1000 -in BoxECDSAsecp256r1.csr -CA RootCA.crt -CAkey RootCA.pem -CAcreateserial -out BoxECDSAsecp256r1.crt`

`cat BoxCertRSA2048.crt BoxCertDSA2048.crt BoxECDSAsecp256r1.crt > allBoxCerts.crt`  

### StreamServer
`openssl genrsa -out RootCA.pem 4096`       Already provided  
`openssl req -new -x509 -days 1500 -key RootCA.pem -out RootCA.crt` Already provided 

SHA256withRSA  
`openssl genrsa -out ServerCertRSA2048.pem 2048`  
`openssl req -new -key ServerCertRSA2048.pem -out ServerCertRSA2048.csr`  
`openssl x509 -req -days 1000 -in ServerCertRSA2048.csr -CA RootCA.crt -CAkey RootCA.pem -CAcreateserial -out ServerCertRSA2048.crt`

SHA256withDSA  
`openssl dsaparam -out Serverdsaparam2048.pem 2048`
`openssl gendsa -out ServerCertDSA2048.pem Serverdsaparam2048.pem`
`openssl x509 -req -days 1000 -in ServerCertDSA2048.csr -CA RootCA.crt -CAkey RootCA.pem -CAcreateserial -out ServerCertDSA2048.crt`

ECDSA, ecspec: secp256r1
`openssl ecparam -genkey -name prime256v1 -out ServerECDSAsecp256r1.pem`
`openssl req -new -key ServerECDSAsecp256r1.pem -out ServerECDSAsecp256r1.csr`  
`openssl x509 -req -days 1000 -in ServerECDSAsecp256r1.csr -CA RootCA.crt -CAkey RootCA.pem -CAcreateserial -out ServerECDSAsecp256r1.crt`

`cat ServerCertRSA2048.crt ServerCertDSA2048.crt ServerECDSAsecp256r1.crt > allServerCerts.crt`  