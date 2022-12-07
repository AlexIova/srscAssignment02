# srscAssignment02

### MAC key
Keystore generated with: `keytool -genseckey -alias mackey -keyalg hmacSHA1 -keysize 128 -keystore mykeystore.jceks -storetype jceks` \
Password: `password` \
Then converted into PKCS12 format: `keytool -importkeystore -srckeystore mykeystore.jceks -destkeystore mykeystore.pkcs12 -deststoretype pkcs12` \

## Commands
### Box
Compile: \
`javac -cp "../bcprov-jdk18on-172.jar:../bcprov-ext-jdk18on-172.jar:." *.java` \
Run: \
`java -cp "../bcprov-jdk18on-172.jar:../bcprov-ext-jdk18on-172.jar:." Box ciao localhost 6789` \

### StreamServer
Compile:\
`javac -cp "../bcprov-jdk18on-172.jar:../bcprov-ext-jdk18on-172.jar:." *.java` \
Run: \
`java -cp "../bcprov-jdk18on-172.jar:../bcprov-ext-jdk18on-172.jar:." StreamServer 6789` \


## Creation certificate

### Box
`openssl genrsa -out RootCA.key 4096`
`openssl req -new -x509 -days 1500 -key RootCA.key -out RootCA.crt`
`openssl genrsa -out BoxCert.key 4096`
`openssl req -new -key BoxCert.key -out BoxCert.csr`
`openssl x509 -req -days 1000 -in BoxCert.csr -CA RootCA.crt -CAkey RootCA.key -CAcreateserial -out BoxCert.crt`
`cat RootCA.crt BoxCert.crt > CertChain.crt`