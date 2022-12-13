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


		/* Variables */
		String hashFunc = "SHA256";
		String kMahInit = "HMac-SHA1";
		String initSig = "SHA256withRSA";


		/* Prepare kmac functions */
		SecretKey mackeySS = UtilsBox.getKeyKS("configs/kmacKeyStoreSS.pkcs12", "mackey", "password", "password");
		Mac macSS = UtilsBox.prepareMacFunc(kMahInit, mackeySS);
		SecretKey mackeyBox = UtilsBox.getKeyKS("configs/kmacKeyStoreBox.pkcs12", "mackey", "password", "password");
		Mac macBox = UtilsBox.prepareMacFunc(kMahInit, mackeyBox);

		/* RSAKeys for signature*/
		PrivateKey kPriv = UtilsBox.readRSAPrivateKey("./certificates/BoxCertRSA2048.pem");
		// X509Certificate cert = UtilsBox.getCertificate("./certificates/BoxCert.crt");

		/* Get DH parameters */
		int sizeParamDH = 2048;
		KeyPair boxPair = UtilsBox.getDHParam(sizeParamDH);
		KeyAgreement boxKeyAgree = KeyAgreement.getInstance("DH", "BC");
		boxKeyAgree.init(boxPair.getPrivate());


		/*--------- Build message ---------*/
		byte[] msg = new byte[] { };
		// nonce
		msg = UtilsBox.byteArrConcat(msg, UtilsBox.intToByteArr(nonce.length));
		msg = UtilsBox.byteArrConcat(msg, nonce);

		// ciphersuites
		byte[] csBytes = UtilsBox.getBytesCS("./configs/preferredCipherSuites");
		msg = UtilsBox.byteArrConcat(msg, UtilsBox.intToByteArr(csBytes.length));
		msg = UtilsBox.byteArrConcat(msg, csBytes);

		// dh parameters
		byte[] boxDHbytes = boxPair.getPublic().getEncoded();
		msg = UtilsBox.byteArrConcat(msg, UtilsBox.intToByteArr(boxDHbytes.length));
		System.out.println("size dh: " + boxDHbytes.length);
		msg = UtilsBox.byteArrConcat(msg, boxDHbytes);
		msg = UtilsBox.byteArrConcat(msg, UtilsBox.intToByteArr(sizeParamDH));

		// certificates
		byte[] certByte = UtilsBox.fileToByte("./certificates/allBoxCerts.crt");
		// System.out.println("Lunghezza certificato: " + certByte.length);
		msg = UtilsBox.byteArrConcat(msg, UtilsBox.intToByteArr(certByte.length));
		msg = UtilsBox.byteArrConcat(msg, certByte);

		// signature
		byte[] sig = UtilsBox.sign(kPriv, initSig, msg);
		msg = UtilsBox.byteArrConcat(msg, sig);
		msg = UtilsBox.byteArrConcat(msg, UtilsBox.intToByteArr(sig.length));

		// hash
		msg = UtilsBox.byteArrConcat(msg, UtilsBox.getHash(hashFunc, msg));
		msg = UtilsBox.byteArrConcat(msg, UtilsBox.intToByteArr(UtilsBox.getHashLen(hashFunc)));

		// Prepare kmac
		msg = UtilsBox.byteArrConcat(msg, macSS.doFinal(msg));
		msg = UtilsBox.byteArrConcat(msg, UtilsBox.intToByteArr(macSS.getMacLength()));

		System.out.println("size of msg: " + msg.length);

		/* Send message */
		UtilsBox.sendTCP(output, msg);


		/******************** Receive reply ********************/

		
		byte[] reply = (byte[]) UtilsBox.recvTCP(input);

		int i = 0;					// Pointer from left
		int j = reply.length;		// Pointer from right

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

		// get CS to use
		int sizeCipherSuite = UtilsBox.byteArrToInt(Arrays.copyOfRange(reply, i, i+4));
		i += 4;
		String cs = UtilsBox.byteToString(Arrays.copyOfRange(reply, i, i+sizeCipherSuite));
		i += sizeCipherSuite;

		System.out.println("cs to use: " + cs);

		// Get DH parameters
		int lenPubDHkey = UtilsBox.byteArrToInt(Arrays.copyOfRange(reply, i, i+4));
		i += 4;
		byte[] pDHserv = Arrays.copyOfRange(reply, i, i+lenPubDHkey);
		i += lenPubDHkey;
		PublicKey servDHkeyPub = UtilsBox.publicDHkeyFromBytes(pDHserv);
		/* Prepare DH key */
		DHParameterSpec dhServParam = ( (javax.crypto.interfaces.DHPublicKey) servDHkeyPub).getParams();
		KeyPairGenerator boxKpairGen = KeyPairGenerator.getInstance("DH", "BC");
        boxKpairGen.initialize(dhServParam);
        KeyPair servPair = boxKpairGen.generateKeyPair();
		boxKeyAgree.doPhase(servDHkeyPub, true);
		System.out.println(UtilsBox.toHex(boxKeyAgree.generateSecret()));

		// Get certificates
		int sizeCerts = UtilsBox.byteArrToInt(Arrays.copyOfRange(reply, i, i+4));
		X509Certificate rootCert = UtilsBox.getCertificate("./certificates/RootCA.crt");
		X509Certificate certStreamServer = UtilsBox.getCertificateFromBytes(Arrays.copyOfRange(reply, i+4, sizeCerts+i+4));
		if(!UtilsBox.verifyCert(certStreamServer, rootCert)){
			System.out.println("ISSUE verifying certificate");
			System.exit(1);
		}

		/* TODO: move this part up, should be done before, I guess... */
		// Verify hash
		int hashSize = UtilsBox.byteArrToInt(Arrays.copyOfRange(reply, j-4, j));
		j -= 4;
		byte[] buffHash = Arrays.copyOfRange(reply, j-hashSize, j);
		j -= hashSize;
		if(!UtilsBox.verifyHash(Arrays.copyOfRange(reply, 0, j), buffHash, hashFunc)){
			System.out.println("Could not verify hash of StreamServer");
		}
		
		/* Now get algs */
		Properties properties = UtilsBox.parserDictionary(cs, "./configs/dictionaryCipherSuites");
		String digSig = properties.getProperty("digital-signature");
		String ecspec = properties.getProperty("ecspec");
		String ciphersuite = properties.getProperty("ciphersuite");
		String keySizeSym = properties.getProperty("key-size-sym");
		String integrity = properties.getProperty("integrity");
		String macKeySize = properties.getProperty("Mackey-size");

		// Verify signature
		int sigSize = UtilsBox.byteArrToInt(Arrays.copyOfRange(reply, j-4, j));
		j -= 4;
		byte[] sigBox = Arrays.copyOfRange(reply, j-sigSize, j);
		j -= sigSize;
		PublicKey kPubBox = certStreamServer.getPublicKey();
		if(!UtilsBox.verifySig(digSig, kPubBox, Arrays.copyOfRange(reply, 0, j), sigBox)){
			System.out.println("Could not verify signature of StreamServer");
		}


		UtilsBox.closeTCPConns(socket, input, output);

	}
	
}

	

