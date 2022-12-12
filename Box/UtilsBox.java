import java.io.*;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Properties;
import java.util.Random;
import java.util.Arrays;
import java.util.Base64;
import java.security.*;
import java.security.cert.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.net.SocketAddress;
import java.net.InetSocketAddress;
import java.net.Socket;

public class UtilsBox {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    static public Socket createTCPSock(String address, int port) throws UnknownHostException, IOException{
        return new Socket(address, port);
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

    static public byte[] getNonceBytes(){
        Random gen = new Random();
        return BigInteger.valueOf(gen.nextInt()).toByteArray();
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

    public static Mac prepareMacFunc(String hfun, Key macKey) 
                                    throws InvalidKeyException, NoSuchAlgorithmException, 
                                            NoSuchProviderException {
        Mac hMac = Mac.getInstance(hfun, "BC");
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
        byte[]  sigBytes = signature.sign();

        return sigBytes;
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

    public static byte[] fileToByte(String path) throws IOException{
        byte[] bytes = Files.readAllBytes(Paths.get(path));
        return bytes;
    }

    public static X509Certificate getCertificateFromBytes(byte[] data) throws CertificateException{

        InputStream dataStream = new BufferedInputStream(new ByteArrayInputStream(data));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
	    X509Certificate cert = (X509Certificate) cf.generateCertificate(dataStream);

		return cert;
	}

    public static Boolean verifySig(String algorithm, PublicKey kPub, byte[] message, byte[] sigBytes)
                                            throws SignatureException, InvalidKeyException,
                                            NoSuchAlgorithmException {

        Signature signature = Signature.getInstance(algorithm);
        signature.initVerify(kPub);
        signature.update(message);

        return signature.verify(sigBytes);

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

        return keyFac.generatePublic(x509KeySpec);
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

}
