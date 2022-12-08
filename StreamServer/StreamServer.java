/*
 * 
 * hjStreamServer.java 
 * Implementatio of a Java-based Streaming Server allowing the
 * the real time streaming of movies encoded in local files
 * The Streaming Server transmits the video frames for real time streaming
 * based (carried in)  UDP packets.
 * Clients can play the streams in real time if they are able to
 * decode the content of the frames in the UDP packets (FFMPEG encoding)
 *
 * To start the Streaming Server use:
 * hjStreamServer <file> <ip address for dissemination> <port dissemination>
 * 
 * Example: hjStreamServer cars.dat localhost 9999
 * In this case the Streaming server will send the movie to localhost port 999
 * where "someone" - a user using a visualizaton tool such as VLC or a BOX
 * is waiting for.
 * There are some available movies in the directory movies. This is the
 * the directory where the server has the movies it can send.
*/

import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.lang.model.type.NullType;
import java.security.Security;
import java.security.cert.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;
import java.nio.charset.StandardCharsets;




class StreamServer {

	public static void main( String []args ) throws Exception {

		if (args.length != 1)
		{
			System.out.println ("Use: StreamServer <port>");
			System.exit(-1);
		}

		/* Create connections */
		ServerSocket serverSocket = new ServerSocket(Integer.parseInt(args[0]));
		Socket socket = serverSocket.accept();
		ObjectOutputStream output = UtilsServer.outTCPStream(socket);
		ObjectInputStream input = UtilsServer.inTCPStream(socket);


		/* Prepare kmac functions */
		SecretKey mackeyBox = UtilsServer.getKeyKS("configs/kmacKeyStoreBox.pkcs12", "mackey", "password", "password");
		Mac macBox = UtilsServer.prepareMacFunc("HmacSHA1", mackeyBox);
		SecretKey mackeySS = UtilsServer.getKeyKS("configs/kmacKeyStoreSS.pkcs12", "mackey", "password", "password");
		Mac macSS = UtilsServer.prepareMacFunc("HmacSHA1", mackeySS);

		
		/*--------------------------- Receive message ---------------------------*/
		byte[] reply = (byte[]) UtilsServer.recvTCP(input);

		int i = 0;		// left pointer to know how much read from reply
		int j = reply.length; 		// right pointer to know how much read from reply
		
		// Verify kmac
		int sizeKmac = UtilsServer.byteArrToInt(Arrays.copyOfRange(reply, reply.length-4, reply.length));
		// System.out.println("DEBUG sizekmac: " + sizeKmac);
		byte[] buffKmacRCV = Arrays.copyOfRange(reply, reply.length-4-sizeKmac, reply.length-4);
		// System.out.println("DEBUG buffKmacRCV: " + buffKmacRCV.length);
		byte[] buffZRcv = Arrays.copyOfRange(reply, 0, reply.length-4-sizeKmac);	// Z of message received
		byte[] buffKmacOWN = macSS.doFinal(buffZRcv);		// Z kmac own calculated
		if(!MessageDigest.isEqual(buffKmacRCV, buffKmacOWN))
			System.out.println("Problem validating message Box");
		j -= (sizeKmac + 4);		// size of kmac and size of int


		// Get nonce
		int sizeNonce = UtilsServer.byteArrToInt(Arrays.copyOfRange(reply, 0, 4));
		byte[] nonce = Arrays.copyOfRange(reply, 4, 4+sizeNonce);
		i += (4 + sizeNonce);


		// Get certificates
		int sizeCerts = UtilsServer.byteArrToInt(Arrays.copyOfRange(reply, i, i+4));
		X509Certificate rootCert = UtilsServer.getCertificate("./certificates/RootCA.crt");
		X509Certificate certBox = UtilsServer.getCertificateFromBytes(Arrays.copyOfRange(reply, i+4, sizeCerts+i+4));
		if(!UtilsServer.verifyCert(certBox, rootCert)){
			System.out.println("ISSUE verifying certificate");
			System.exit(1);
		}

		// Verify signature
		int sigSize = UtilsServer.byteArrToInt(Arrays.copyOfRange(reply, j-4, j));
		j -= 4;
		byte[] sigBox = Arrays.copyOfRange(reply, j-sigSize, j);
		j -= sigSize;
		PublicKey kPubBox = certBox.getPublicKey();
		if(!UtilsServer.verifySig("SHA256withRSA", kPubBox, Arrays.copyOfRange(reply, 0, j), sigBox)){
			System.out.println("Could not verify signature of Box");
		}

		/*--------------------------- Build message ---------------------------*/
		byte[] msg = new byte[] { };
		// send nonce
		msg = UtilsServer.byteArrConcat(msg, UtilsServer.intToByteArr(nonce.length));
		msg = UtilsServer.byteArrConcat(msg, nonce);

		// Send certificate
		byte[] certByte = UtilsServer.fileToByte("./certificates/StreamServerCert.crt");
		System.out.println("Lunghezza: " + certByte.length);
		msg = UtilsServer.byteArrConcat(msg, UtilsServer.intToByteArr(certByte.length));
		msg = UtilsServer.byteArrConcat(msg, certByte);

		// Send signature
		PrivateKey kPriv = UtilsServer.readRSAPrivateKey("./certificates/StreamServerCert.pem");
		byte[] sig = UtilsServer.sign(kPriv, "SHA256withRSA", msg);
		msg = UtilsServer.byteArrConcat(msg, sig);
		msg = UtilsServer.byteArrConcat(msg, UtilsServer.intToByteArr(sig.length));


		// Prepare kmac
		msg = UtilsServer.byteArrConcat(msg, macBox.doFinal(msg));
		msg = UtilsServer.byteArrConcat(msg, UtilsServer.intToByteArr(macBox.getMacLength()));

		UtilsServer.sendTCP(output, msg);

		serverSocket.close();
		UtilsServer.closeTCPConns(socket, input, output);

	}


}






