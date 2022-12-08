import java.io.*;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.file.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
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
        byte[]  sigBytes = signature.sign();

        return sigBytes;
    }

    public static Boolean verifyKmac(byte[] message, Mac macF){
        
        int sizeKmac = UtilsServer.byteArrToInt(Arrays.copyOfRange(message, message.length-4, message.length));
		System.out.println("DEBUG sizekmac: " + sizeKmac);
		byte[] buffKmacRCV = Arrays.copyOfRange(message, message.length-4-sizeKmac, message.length-4);
		System.out.println("DEBUG buffKmacRCV: " + buffKmacRCV.length);
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

}