import java.io.*;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Arrays;
import java.util.Properties;
import java.util.Random;
import java.security.spec.InvalidKeySpecException;
import java.security.cert.*;





public class UtilsServer {

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
                                    throws InvalidKeyException, NoSuchAlgorithmException {
        Mac hMac = Mac.getInstance(hCheck);
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

}