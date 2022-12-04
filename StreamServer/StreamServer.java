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
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.lang.model.type.NullType;
import java.security.Security;
import java.util.Arrays;
import java.util.Properties;
import java.nio.charset.StandardCharsets;




class StreamServer {

	public static void main( String []args ) throws Exception {

		ServerSocket serverSocket = new ServerSocket(6868);		// TODO: need to later change the port
		Socket socket = serverSocket.accept();
		ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
		ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
		
		output.writeObject("Hello I'm StreamServer");

		String reply = (String) input.readObject();
		System.out.println("Reply:\t" + reply);

		serverSocket.close();
	}


}





