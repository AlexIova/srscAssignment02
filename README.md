# srscAssignment02

### MAC key
Keystore generated with: `keytool -genseckey -alias mackey -keyalg hmacSHA1 -keysize 128 -keystore mykeystore.jceks -storetype jceks` \
Password: `password` \
Then converted into PKCS12 format: `keytool -importkeystore -srckeystore mykeystore.jceks -destkeystore mykeystore.pkcs12 -deststoretype pkcs12` \
