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

		System.out.println("nonce:\t" + UtilsBox.byteArrToInt(nonce));

		/*
		SecretKey mackeySS = UtilsBox.getKeyKS("configs/kmacKeyStoreSS.pkcs12", "mackey", "password", "password");
		Mac macSS = UtilsBox.prepareMacFunc("HMac-SHA1", mackeySS);
		SecretKey mackeyBox = UtilsBox.getKeyKS("configs/kmacKeyStoreBox.pkcs12", "mackey", "password", "password");
		Mac macBox = UtilsBox.prepareMacFunc("HMac-SHA1", mackeySS);
		*/

		/* Build message */
		byte[] msg = new byte[] { };
		// send nonce
		msg = UtilsBox.byteArrConcat(msg, UtilsBox.intToByteArr(nonce.length));
		System.out.println("debug: " + UtilsBox.intToByteArr(nonce.length).length);
		msg = UtilsBox.byteArrConcat(msg, nonce);

		
		/* Send message */
		UtilsBox.sendTCP(output, msg);


		/* Receive reply */
		byte[] reply = (byte[]) UtilsBox.recvTCP(input); 

		/* Get nonce */
		int sizeNonceReply = UtilsBox.byteArrToInt(Arrays.copyOfRange(reply, 0, 4));
		byte[] nonceReply = Arrays.copyOfRange(reply, 4, 4 + sizeNonceReply);

		// Compare nonces
		if (Arrays.equals(nonce, nonceReply)){
			System.out.println("Tutto bene");
		}

		UtilsBox.closeTCPConns(socket, input, output);

	}
	
}

	

