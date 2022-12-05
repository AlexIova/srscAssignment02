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
		
		/* Receive message */
		byte[] reply = (byte[]) UtilsServer.recvTCP(input);

		// Get nonce
		int sizeNonce = UtilsServer.byteArrToInt(Arrays.copyOfRange(reply, 0, 4));
		byte[] nonce = Arrays.copyOfRange(reply, 4, 4+sizeNonce);

		System.out.println("recv:\t" + UtilsServer.byteArrToInt(nonce));


		/* Build message */
		byte[] msg = new byte[] { };
		// send nonce
		msg = UtilsServer.byteArrConcat(msg, UtilsServer.intToByteArr(nonce.length));
		msg = UtilsServer.byteArrConcat(msg, nonce);

		/*
		SecretKey mackey = UtilsBox.getKeyKS("configs/kmacKeyStoreBox.pkcs12", "mackey", "password", "password");
		System.out.println(new String(Base64.getEncoder().encode(mackey.getEncoded())));
		*/

		UtilsServer.sendTCP(output, msg);

		serverSocket.close();
		UtilsServer.closeTCPConns(socket, input, output);

	}


}






