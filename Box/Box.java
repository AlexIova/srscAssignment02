/* hjBox, 22/23
 *
 * This is the implementation of a Box to receive streamed UDP packets
 * (with media segments as payloads encoding MPEG4 frames)
 * The code is inspired (in fact very similar) to the code presented,
 * available, used and discussed in Labs (Lab 2, Part I)
 *
 * You can use this material as a starting point for your Box implementation
 * in TP1, according to the TP1 requirements
 */

import java.io.*;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.MulticastSocket;
import java.net.Socket;
import java.net.InetSocketAddress;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.util.Arrays;
import java.util.Base64;
import java.util.ArrayList;
import java.util.Properties;
import java.util.Set;
import java.util.Random;
import java.util.stream.Collectors;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.cert.*;

import java.security.spec.InvalidKeySpecException;
import java.security.Security;

class Box {    
    
    public static void main(String[] args) throws Exception {

		if (args.length != 3)
		{
			System.out.println ("Use: Box <movie> <address> <port>");
			System.exit(-1);
		}

		Socket socket = UtilsBox.createTCPSock(args[1], Integer.parseInt(args[2]));
		ObjectOutputStream output = UtilsBox.outTCPStream(socket);
		ObjectInputStream input = UtilsBox.inTCPStream(socket);

		byte[] nonce = UtilsBox.getNonceBytes();

		// System.out.println("DEBUG nonce:\t" + UtilsBox.byteArrToInt(nonce));


		/* Prepare kmac functions */
		SecretKey mackeySS = UtilsBox.getKeyKS("configs/kmacKeyStoreSS.pkcs12", "mackey", "password", "password");
		Mac macSS = UtilsBox.prepareMacFunc("HMac-SHA1", mackeySS);
		SecretKey mackeyBox = UtilsBox.getKeyKS("configs/kmacKeyStoreBox.pkcs12", "mackey", "password", "password");
		Mac macBox = UtilsBox.prepareMacFunc("HMac-SHA1", mackeyBox);

		/* RSAKeys */
		PrivateKey kPriv = UtilsBox.readRSAPrivateKey("./certificates/BoxCert.pem");
		X509Certificate cert = UtilsBox.getCertificate("./certificates/BoxCert.crt");

		/*--------- Build message ---------*/
		byte[] msg = new byte[] { };
		// send nonce
		msg = UtilsBox.byteArrConcat(msg, UtilsBox.intToByteArr(nonce.length));
		msg = UtilsBox.byteArrConcat(msg, nonce);

		// send certificate
		byte[] certByte = UtilsBox.fileToByte("./certificates/BoxCert.crt");
		System.out.println("Lunghezza: " + certByte.length);
		msg = UtilsBox.byteArrConcat(msg, UtilsBox.intToByteArr(certByte.length));
		msg = UtilsBox.byteArrConcat(msg, certByte);

		// signature
		byte[] sig = UtilsBox.sign(kPriv, "SHA256withRSA", msg);
		msg = UtilsBox.byteArrConcat(msg, sig);
		msg = UtilsBox.byteArrConcat(msg, UtilsBox.intToByteArr(sig.length));

		// Prepare kmac
		msg = UtilsBox.byteArrConcat(msg, macSS.doFinal(msg));
		msg = UtilsBox.byteArrConcat(msg, UtilsBox.intToByteArr(macSS.getMacLength()));


		
		/* Send message */
		UtilsBox.sendTCP(output, msg);


		int i = 0;		// Pointer from left
		int j = 0;		// Pointer from right
		/* Receive reply */
		byte[] reply = (byte[]) UtilsBox.recvTCP(input);

		j = reply.length;

		/* Get kmac */
		int sizeKmac = UtilsBox.byteArrToInt(Arrays.copyOfRange(reply, reply.length-4, reply.length));
		// System.out.println("DEBUG sizekmac: " + sizeKmac);
		byte[] buffKmacRCV = Arrays.copyOfRange(reply, reply.length-4-sizeKmac, reply.length-4);	// kmac received
		// System.out.println("DEBUG buffKmacRCV: " + buffKmacRCV.length);
		byte[] buffZRcv = Arrays.copyOfRange(reply, 0, reply.length-4-sizeKmac);	// Z of message received
		byte[] buffKmacOWN = macBox.doFinal(buffZRcv);		// Z kmac own calculated
		if( !MessageDigest.isEqual(buffKmacRCV, buffKmacOWN) ){
			System.out.println("Problem validating message SS");
		}
		j = j - sizeKmac - 4;		// size of kmac and size of int

		// Get nonce
		int sizeNonceReply = UtilsBox.byteArrToInt(Arrays.copyOfRange(reply, 0, 4));
		byte[] nonceReply = Arrays.copyOfRange(reply, 4, 4 + sizeNonceReply);
		if (Arrays.equals(nonce, nonceReply)){
			System.out.println("Nonce corresponds");
		}
		i += 4 + sizeNonceReply;
		
		// Get certificates
		int sizeCerts = UtilsBox.byteArrToInt(Arrays.copyOfRange(reply, i, i+4));
		X509Certificate rootCert = UtilsBox.getCertificate("./certificates/RootCA.crt");
		X509Certificate certStreamServer = UtilsBox.getCertificateFromBytes(Arrays.copyOfRange(reply, i+4, sizeCerts+i+4));
		if(!UtilsBox.verifyCert(certStreamServer, rootCert)){
			System.out.println("ISSUE verifying certificate");
			System.exit(1);
		}

		// Verify signature
		int sigSize = UtilsBox.byteArrToInt(Arrays.copyOfRange(reply, j-4, j));
		j -= 4;
		byte[] sigBox = Arrays.copyOfRange(reply, j-sigSize, j);
		j -= sigSize;
		PublicKey kPubBox = certStreamServer.getPublicKey();
		if(!UtilsBox.verifySig("SHA256withRSA", kPubBox, Arrays.copyOfRange(reply, 0, j), sigBox)){
			System.out.println("Could not verify signature of StreamServer");
		}


		UtilsBox.closeTCPConns(socket, input, output);

	}
	
}

	

