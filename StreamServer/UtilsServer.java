import java.io.*;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.file.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;
import java.util.Random;
import java.security.spec.*;
import java.security.cert.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;




public class UtilsServer {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    static public ObjectOutputStream outTCPStream(Socket socket) throws IOException{
        return new ObjectOutputStream(socket.getOutputStream());
    }

    static public ObjectInputStream inTCPStream(Socket socket) throws IOException{
        return new ObjectInputStream(socket.getInputStream());
    }

    static public void sendTCP(ObjectOutputStream output, Object payload) throws IOException{
        output.writeObject(payload);
    }

    static public Object recvTCP(ObjectInputStream input) throws ClassNotFoundException, IOException{
        return input.readObject();
    }

    static public void closeTCPConns(Socket socket, ObjectInputStream input, ObjectOutputStream output) throws IOException{
        socket.close();
        input.close();
        output.close();
    }

    static public int byteArrToInt(byte[] bytes){
        int value = 0;
        for (byte b : bytes) {
            value = (value << 8) + (b & 0xFF);
        }
        return value;
    }

    static public byte[] intToByteArr(int value) {
        return new byte[] {
                (byte)(value >> 24),
                (byte)(value >> 16),
                (byte)(value >> 8),
                (byte)value};
    }

    public static byte[] serializeObject(Object obj) throws IOException{
        ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bytesOut);
        oos.writeObject(obj);
        oos.flush();
        byte[] bytes = bytesOut.toByteArray();
        bytesOut.close();
        oos.close();
        return bytes;
    }

    public static SecretKey getKeyKS(String file, String alias, String passwordKS, String passwordKey) 
                                    throws UnrecoverableKeyException, KeyStoreException, 
                                            NoSuchAlgorithmException, CertificateException, 
                                            FileNotFoundException, IOException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(new FileInputStream(new File(file)), passwordKS.toCharArray());
		SecretKey key = (SecretKey) ks.getKey(alias, passwordKey.toCharArray());
        return key;
    }

    public static Mac prepareMacFunc(String hCheck, Key macKey) 
                                    throws InvalidKeyException, NoSuchAlgorithmException, 
                                            NoSuchProviderException {
        Mac hMac = Mac.getInstance(hCheck, "BC");
        hMac.init(macKey);
        return hMac;
	}


    public static byte[] byteArrConcat(byte[] a, byte[] b){
		if (a == null || a.length == 0) return b;

		if (b == null || b.length == 0) return a;

		byte[] c = new byte[a.length + b.length];
		int ctr = 0;

		for (int i = 0; i < a.length; i++) 
			c[ctr++] = a[i];

		for (int i = 0; i < b.length; i++)
			c[ctr++] = b[i];

		return c;
	}

    public static X509Certificate getCertificate(String path) 
                                        throws CertificateException, FileNotFoundException{

		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		
	    InputStream in = new BufferedInputStream(new FileInputStream(path));
	    X509Certificate cert = (X509Certificate) cf.generateCertificate(in);

		return cert;
	}

    public static PrivateKey readRSAPrivateKey(String path) 
                                        throws NoSuchAlgorithmException, NoSuchProviderException,
                                                InvalidKeySpecException, IOException{

        String keyString = new String(Files.readAllBytes(Paths.get(path)), Charset.defaultCharset());
    
        String privateKeyPEM = keyString
          .replace("-----BEGIN PRIVATE KEY-----", "")
          .replaceAll(System.lineSeparator(), "")
          .replace("-----END PRIVATE KEY-----", "");
    
        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        PrivateKey key = kf.generatePrivate(keySpec);
        return key;

    }

    public static byte[] sign(PrivateKey kPriv, String algorithm, byte[] message)
                                                            throws SignatureException, InvalidKeyException,
                                                            NoSuchAlgorithmException, NoSuchProviderException {

        Signature signature = Signature.getInstance(algorithm, "BC");
        signature.initSign(kPriv);
        signature.update(message);
        byte[] sigBytes = signature.sign();

        return sigBytes;
    }

    public static Boolean verifyKmac(byte[] message, Mac macF){
        
        int sizeKmac = UtilsServer.byteArrToInt(Arrays.copyOfRange(message, message.length-4, message.length));
		byte[] buffKmacRCV = Arrays.copyOfRange(message, message.length-4-sizeKmac, message.length-4);
		byte[] buffZRcv = Arrays.copyOfRange(message, 0, message.length-4-sizeKmac);	// Z of message received
		byte[] buffKmacOWN = macF.doFinal(buffZRcv);		// Z kmac own calculated
        
        return MessageDigest.isEqual(buffKmacRCV, buffKmacOWN);

    }

    public static X509Certificate getCertificateFromBytes(byte[] data) throws CertificateException{

        InputStream dataStream = new BufferedInputStream(new ByteArrayInputStream(data));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
	    X509Certificate cert = (X509Certificate) cf.generateCertificate(dataStream);

		return cert;
	}

    public static Boolean verifyCert(X509Certificate cert, X509Certificate root){
        try {
            cert.verify(root.getPublicKey()); 
            return true;
        } 
        catch (CertificateException | NoSuchAlgorithmException | 
                InvalidKeyException | NoSuchProviderException 
                | SignatureException e) {
            System.out.println(e);
            return false;
        }
    }

    public static Boolean verifySig(String algorithm, PublicKey kPub, byte[] message, byte[] sigBytes)
                                            throws SignatureException, InvalidKeyException,
                                            NoSuchAlgorithmException {

        Signature signature = Signature.getInstance(algorithm);
        signature.initVerify(kPub);
        signature.update(message);

        return signature.verify(sigBytes);

    }

    public static byte[] fileToByte(String path) throws IOException{
        byte[] bytes = Files.readAllBytes(Paths.get(path));
        return bytes;
    }

    public static KeyPair getDHParam(int size) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
                                                NoSuchProviderException {

        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("DH", "BC");
        keyGenerator.initialize(size);

        return keyGenerator.genKeyPair();
    }

    public static KeyPair getDHFromParam(BigInteger p, BigInteger g) throws NoSuchAlgorithmException,
                                                InvalidAlgorithmParameterException, NoSuchProviderException {

        DHParameterSpec dhParams = new DHParameterSpec(p, g);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");
        keyGen.initialize(dhParams);

        return keyGen.generateKeyPair();
    }

    public static String toHex(byte[] data){
        int length = data.length;
        StringBuffer buf = new StringBuffer();
        String	digits = "0123456789abcdef";
        
        for (int i = 0; i != length; i++){
            int	v = data[i] & 0xff;
            
            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }
        
        return buf.toString();
    }

    public static PublicKey publicDHkeyFromBytes(byte[] bytes) throws 
                                                NoSuchAlgorithmException, NoSuchProviderException, 
                                                InvalidKeySpecException{
        
        KeyFactory keyFac = KeyFactory.getInstance("DH", "BC");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(bytes);

        PublicKey pubK = keyFac.generatePublic(x509KeySpec);

        return pubK;
    }

    public static Boolean verifyHash(byte[] mine, byte[] toVer, String hCheck)
                                                throws NoSuchAlgorithmException, NoSuchProviderException{

        MessageDigest hfun = MessageDigest.getInstance(hCheck, "BC");
        byte[] buff = hfun.digest(mine);

        return MessageDigest.isEqual(buff, toVer);
    }

    public static int getHashLen(String hCheck) throws NoSuchAlgorithmException, NoSuchProviderException{
        return MessageDigest.getInstance(hCheck, "BC").getDigestLength();
    }

    public static byte[] getHash(String hCheck, byte[] buff) throws NoSuchAlgorithmException, NoSuchProviderException{

        MessageDigest hfun = MessageDigest.getInstance(hCheck, "BC");

        return hfun.digest(buff);
    }

    private static String fileToString(String path) throws IOException{

        return new String(Files.readAllBytes(Paths.get(path)), Charset.defaultCharset());
    
    }

    public static byte[] getBytesCS(String path) throws IOException{

        String cs = fileToString(path);
        return cs.getBytes();

    }

    public static String byteToString(byte[] bytes){
        return new String(bytes);
    }

    /* choose CS to use */
    public static String chooseCS(byte[] recv, String path) throws IOException{
        
        String[] serverCS = fileToString(path).split(",");
        String[] boxCS = byteToString(recv).split(",");

        for(String sServer : serverCS){
            for(String sBox: boxCS){
                if(sBox.equals(sServer))
                    return sServer;
            }
        }

        return null;
        
    }

    public static X509Certificate[] getArrCertificate(byte[] bytes) throws CertificateException{
        
        String chain = new String(bytes);
        String[] arrCerts = chain.split("-----END CERTIFICATE-----");
        for(int i = 0; i < arrCerts.length-1; i++){
            arrCerts[i] += "-----END CERTIFICATE-----";
        }
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        ArrayList<X509Certificate> certs = new ArrayList<X509Certificate>();
        X509Certificate tmpCert = null;
        for(int i = 0; i < arrCerts.length-1; i++){
            tmpCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(arrCerts[i].getBytes()));
            certs.add(tmpCert);
        }

        X509Certificate[] x509cert = new X509Certificate[arrCerts.length-1];
        x509cert = certs.toArray(x509cert);

        return x509cert;

    }

    public static X509Certificate getSpecificCertificate(String alg, X509Certificate[] certArr){

        if(alg.equals("ECDSA")){
            alg = "EC";
        } else if (alg.equals("SHA256withDSA")){
            alg = "DSA";
        } else if (alg.equals("SHA256withRSA")){
            alg = "RSA";
        }

        for(X509Certificate cert : certArr){
            if(cert.getPublicKey().getAlgorithm().equals(alg)){
                return cert;
            }
        }

        return null;

    }


    public static Properties parserDictionary(String CS, String pathFile) 
                                        throws FileNotFoundException, IOException{

		Properties properties = new Properties();
		String start = "<" + CS + ">";
		String finish = "</" + CS + ">";
        BufferedReader br = new BufferedReader(new FileReader(pathFile));
        StringBuilder sb = new StringBuilder();
        String currentLine;
        // find beginning
        while ((currentLine = br.readLine()) != null && !(currentLine.contains(start))) {
            ;
        }
        // find end
        while ((currentLine = br.readLine()) != null && !(currentLine.contains(finish))) {
            if (currentLine.indexOf("//") != -1)	// remove comments
                currentLine = currentLine.substring(0, currentLine.indexOf("//"));
            sb.append(currentLine.replaceAll("\\s+",""));		// take out whitespace
            sb.append("\n");
        }
        if(sb.length() == 0){
            System.out.println("Can't find CS in dictionary file");
            System.exit(-1);
        }
        properties.load(new ByteArrayInputStream( sb.toString().getBytes() ));
        br.close();

		return properties;

	}

    public static String chooseCertificate(String alg){
        if(alg.equals("SHA256withRSA")){
            return "./certificates/ServerCertRSA2048.crt";
        } 
        else if (alg.equals("SHA256withDSA")){
            return "./certificates/ServerCertDSA2048.crt";
        } 
        else if (alg.equals("ECDSA")){
            return "./certificates/ServerECDSAsecp256r1.crt";
        }
        else {
            return null;
        }

    }

    public static PrivateKey readGeneralPrivateKey(String alg) 
                                throws NoSuchAlgorithmException, InvalidKeySpecException, 
                                        IOException, NoSuchProviderException {

        String path;
        String type;
        if(alg.equals("SHA256withRSA")){
            path =  "./certificates/ServerCertRSA2048.pem";
            type = "RSA";
        } 
        else if (alg.equals("SHA256withDSA")){
            path = "./certificates/ServerCertDSA2048.pem";
            type = "DSA";
        } 
        else if (alg.equals("ECDSA")){
            path = "./certificates/ServerECDSAsecp256r1.pem";
            type = "EC";
        }
        else {
            return null;
        }
        String keyString = new String(Files.readAllBytes(Paths.get(path)), Charset.defaultCharset());

        String privateKeyPEM = keyString
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replaceAll(System.lineSeparator(), "")
            .replace("-----END PRIVATE KEY-----", "");

        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        KeyFactory kf = KeyFactory.getInstance(type, "BC");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        PrivateKey key = kf.generatePrivate(keySpec);
        return key;    

    }

    public static byte[] hashToKey(byte[] bytes, int size) 
                                throws NoSuchAlgorithmException, NoSuchProviderException{

        String hashFunc;
        if(size == 128){
            hashFunc = "MD5";
        }
        else if(size == 256){
            hashFunc = "SHA256";
        }
        else {
            return null;
        }
        MessageDigest hfun = MessageDigest.getInstance(hashFunc, "BC");

        return hfun.digest(bytes);

    }


    public static byte[] preparePacketMac(byte[] data, Cipher symC, PrivateKey sigKey, String digSig, Mac macF) 
                                            throws IllegalBlockSizeException, SignatureException, 
                                                    BadPaddingException, InvalidKeyException, 
                                                    NoSuchAlgorithmException, NoSuchProviderException {
        
        byte[] msg = new byte[] { };
        byte[] enc = symC.doFinal(data);
        msg = byteArrConcat(msg, enc);
        byte[] signature = sign(sigKey, digSig, msg);
        msg = byteArrConcat(msg, signature);
        msg = byteArrConcat(msg, intToByteArr(signature.length));
        byte[] mac = macF.doFinal(msg);
        msg = byteArrConcat(msg, mac);
    
        return msg;

    }


    public static byte[] preparePacketHash(byte[] data, Cipher symC, PrivateKey sigKey, String digSig, MessageDigest hashF) 
                                            throws IllegalBlockSizeException, SignatureException, 
                                                    BadPaddingException, InvalidKeyException, 
                                                    NoSuchAlgorithmException, NoSuchProviderException {
        
        byte[] msg = new byte[] { };
        byte[] enc = symC.doFinal(data);
        msg = byteArrConcat(msg, enc);
        byte[] signature = sign(sigKey, digSig, msg);
        msg = byteArrConcat(msg, signature);
        msg = byteArrConcat(msg, intToByteArr(signature.length));
        byte[] hash = hashF.digest(msg);
        msg = byteArrConcat(msg, hash);
    
        return msg;

    }


    public static Mac prepareMacFunc(String hCheck, SecretKey macKey) 
                                        throws NoSuchAlgorithmException, InvalidKeyException, 
                                            NoSuchProviderException {

        Mac hMac = Mac.getInstance(hCheck, "BC");
        hMac.init(macKey);
        return hMac;

	}

    public static Cipher prepareSymEnc(String alg, SecretKey key, IvParameterSpec iv) 
                                        throws NoSuchAlgorithmException, InvalidKeyException, 
                                            NoSuchProviderException, NoSuchPaddingException,
                                            InvalidAlgorithmParameterException {
        
        Cipher cipher = Cipher.getInstance(alg, "BC");
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher;

    }

    public static Cipher prepareSymDec(String alg, SecretKey key, IvParameterSpec iv) 
                                        throws NoSuchAlgorithmException, InvalidKeyException, 
                                            NoSuchProviderException, NoSuchPaddingException,
                                            InvalidAlgorithmParameterException {
        
        Cipher cipher = Cipher.getInstance(alg, "BC");
		cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return cipher;

    }

    public static Cipher prepareSymDec(String alg, SecretKey key) 
                                        throws NoSuchAlgorithmException, InvalidKeyException, 
                                            NoSuchProviderException, NoSuchPaddingException {
        
        Cipher cipher = Cipher.getInstance(alg, "BC");
		cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher;

    }

    
    public static byte[] verifyHASHAndDecrypt(byte[] data, Cipher symC, PublicKey sigKey, String digSig, MessageDigest hashF)
                                                throws SignatureException, IllegalBlockSizeException,
                                                    InvalidKeyException, BadPaddingException,
                                                    NoSuchAlgorithmException {
        
        int j = data.length;
        byte[] y = Arrays.copyOfRange(data, 0, j-hashF.getDigestLength());
        byte[] digest = hashF.digest(y);
        byte[] hash = Arrays.copyOfRange(data, j-hashF.getDigestLength(), j);
        if(!MessageDigest.isEqual(hash, digest)){
            System.out.println("Problem verifying hash");
            return null;
        }
        j -= hashF.getDigestLength();
        int sizeSig = byteArrToInt(Arrays.copyOfRange(data, j-4, j));
        j -= 4;
        byte[] signature = Arrays.copyOfRange(data, j-sizeSig, j);
        j -= sizeSig;
        byte[] encData = Arrays.copyOfRange(data, 0, j);
        if(!verifySig(digSig, sigKey, encData, signature)){
            System.out.println("Problem verifying signature");
            return null;
        }
        byte[] decData = symC.doFinal(encData);
        
        return decData;

    }

    public static byte[] verifyMACAndDecrypt(byte[] data, Cipher symC, PublicKey sigKey, String digSig, Mac macF)
                                                throws SignatureException, IllegalBlockSizeException,
                                                    InvalidKeyException, BadPaddingException,
                                                    NoSuchAlgorithmException {

        int j = data.length;
        byte[] y = Arrays.copyOfRange(data, 0, j-macF.getMacLength());
        byte[] integrity = macF.doFinal(y);
        byte[] hmac = Arrays.copyOfRange(data, j-macF.getMacLength(), j);
        if(!Arrays.equals(hmac, integrity)){
            System.out.println("Problem verifying hmac");
            return null;
        }
        j -= macF.getMacLength();
        int sizeSig = byteArrToInt(Arrays.copyOfRange(data, j-4, j));
        j -= 4;
        byte[] signature = Arrays.copyOfRange(data, j-sizeSig, j);
        j -= sizeSig;
        byte[] encData = Arrays.copyOfRange(data, 0, j);
        if(!verifySig(digSig, sigKey, encData, signature)){
            System.out.println("Problem verifying signature");
            return null;
        }
        byte[] decData = symC.doFinal(encData);
        
        return decData;

    }
    
    public static void sendUDP(DatagramSocket sock, byte[] msg, String hostname, int port) throws IOException{
        
        InetSocketAddress addr = new InetSocketAddress( hostname, port);
        sock.send(new DatagramPacket(msg, msg.length, addr));

    }

    public static void sendNull(DatagramSocket sock, String hostname, int port) throws IOException{
		byte[]  nullByte = new byte[] { 
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00
			};

		sendUDP(sock, nullByte, hostname, port);
	}

}