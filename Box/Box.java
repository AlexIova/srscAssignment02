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

		System.out.println("DEBUG nonce:\t" + UtilsBox.byteArrToInt(nonce));

		
		/* Prepare kmac functions */
		SecretKey mackeySS = UtilsBox.getKeyKS("configs/kmacKeyStoreSS.pkcs12", "mackey", "password", "password");
		Mac macSS = UtilsBox.prepareMacFunc("HMac-SHA1", mackeySS);
		SecretKey mackeyBox = UtilsBox.getKeyKS("configs/kmacKeyStoreBox.pkcs12", "mackey", "password", "password");
		Mac macBox = UtilsBox.prepareMacFunc("HMac-SHA1", mackeyBox);


		/*--------- Build message ---------*/
		byte[] msg = new byte[] { };
		// send nonce
		msg = UtilsBox.byteArrConcat(msg, UtilsBox.intToByteArr(nonce.length));
		msg = UtilsBox.byteArrConcat(msg, nonce);
		// Prepare kmac
		msg = UtilsBox.byteArrConcat(msg, macSS.doFinal(msg));
		msg = UtilsBox.byteArrConcat(msg, UtilsBox.intToByteArr(macSS.getMacLength()));

		
		/* Send message */
		UtilsBox.sendTCP(output, msg);


		/* Receive reply */
		byte[] reply = (byte[]) UtilsBox.recvTCP(input); 

		/* Get kmac */
		int sizeKmac = UtilsBox.byteArrToInt(Arrays.copyOfRange(reply, reply.length-4, reply.length));
		System.out.println("DEBUG sizekmac: " + sizeKmac);
		byte[] buffKmacRCV = Arrays.copyOfRange(reply, reply.length-4-sizeKmac, reply.length-4);	// kmac received
		System.out.println("DEBUG buffKmacRCV: " + buffKmacRCV.length);
		byte[] buffZRcv = Arrays.copyOfRange(reply, 0, reply.length-4-sizeKmac);	// Z of message received
		byte[] buffKmacOWN = macBox.doFinal(buffZRcv);		// Z kmac own calculated
		// verify rest of msg
		if( MessageDigest.isEqual(buffKmacRCV, buffKmacOWN) ){
			System.out.println("Validated Message SS");
		}
		else {
			System.out.println("Problem validating message SS");
		}
		

		/* Get nonce */
		int sizeNonceReply = UtilsBox.byteArrToInt(Arrays.copyOfRange(reply, 0, 4));
		byte[] nonceReply = Arrays.copyOfRange(reply, 4, 4 + sizeNonceReply);
		// Compare nonces
		if (Arrays.equals(nonce, nonceReply)){
			System.out.println("Nonce corresponds");
		}

		UtilsBox.closeTCPConns(socket, input, output);

	}
	
}

	

