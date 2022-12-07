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
