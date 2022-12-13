import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.lang.model.type.NullType;

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

		/* Variables */
		String hashFunc = "SHA256";
		String kMahInit = "HMac-SHA1";
		String initSig = "SHA256withRSA";

		/* Prepare kmac functions */
		SecretKey mackeyBox = UtilsServer.getKeyKS("configs/kmacKeyStoreBox.pkcs12", "mackey", "password", "password");
		Mac macBox = UtilsServer.prepareMacFunc(kMahInit, mackeyBox);
		SecretKey mackeySS = UtilsServer.getKeyKS("configs/kmacKeyStoreSS.pkcs12", "mackey", "password", "password");
		Mac macSS = UtilsServer.prepareMacFunc(kMahInit, mackeySS);

		/*--------------------------- Receive message ---------------------------*/
		byte[] reply = (byte[]) UtilsServer.recvTCP(input);

		int i = 0;					// left pointer to know how much read from reply
		int j = reply.length; 		// right pointer to know how much read from reply
		
		// Verify kmac
		int sizeKmac = UtilsServer.byteArrToInt(Arrays.copyOfRange(reply, reply.length-4, reply.length));
		byte[] buffKmacRCV = Arrays.copyOfRange(reply, reply.length-4-sizeKmac, reply.length-4);
		byte[] buffZRcv = Arrays.copyOfRange(reply, 0, reply.length-4-sizeKmac);	// Z of message received
		byte[] buffKmacOWN = macSS.doFinal(buffZRcv);		// Z kmac own calculated
		if(!MessageDigest.isEqual(buffKmacRCV, buffKmacOWN))
			System.out.println("Problem validating message Box");
		j -= (sizeKmac + 4);		// size of kmac and size of int

		// Get nonce
		int sizeNonce = UtilsServer.byteArrToInt(Arrays.copyOfRange(reply, 0, 4));
		byte[] nonce = Arrays.copyOfRange(reply, 4, 4+sizeNonce);
		i += (4 + sizeNonce);

		// get ciphersuites
		int sizeCS = UtilsServer.byteArrToInt(Arrays.copyOfRange(reply, i, i+4));
		i += 4;
		String cs = UtilsServer.chooseCS(Arrays.copyOfRange(reply, i, i+sizeCS), "./configs/preferredCipherSuites");
		i += sizeCS;

		// Get DH parameters
		int lenPubDHkey = UtilsServer.byteArrToInt(Arrays.copyOfRange(reply, i, i+4));
		byte[] pDHbox = Arrays.copyOfRange(reply, i+4, i+4+lenPubDHkey);
		i += (4 + lenPubDHkey);
		PublicKey boxDHkeyPub = UtilsServer.publicDHkeyFromBytes(pDHbox);
		int sizeParamDH = UtilsServer.byteArrToInt(Arrays.copyOfRange(reply, i, i+4));
		i += 4;
		/* Prepare DH key */
		DHParameterSpec dhBoxParam = ( (javax.crypto.interfaces.DHPublicKey) boxDHkeyPub).getParams();		
        KeyPairGenerator servKpairGen = KeyPairGenerator.getInstance("DH", "BC");
        servKpairGen.initialize(dhBoxParam);
        KeyPair servPair = servKpairGen.generateKeyPair();
		KeyAgreement serverKeyAgree = KeyAgreement.getInstance("DH", "BC");
        serverKeyAgree.init(servPair.getPrivate());
		serverKeyAgree.doPhase(boxDHkeyPub, true);
		// System.out.println(UtilsServer.toHex(serverKeyAgree.generateSecret()));

		// Get certificates
		int sizeCerts = UtilsServer.byteArrToInt(Arrays.copyOfRange(reply, i, i+4));
		X509Certificate rootCert = UtilsServer.getCertificate("./certificates/RootCA.crt");
		X509Certificate[] certsBox = UtilsServer.getArrCertificate(Arrays.copyOfRange(reply, i+4, sizeCerts+i+4));
		for (X509Certificate cert : certsBox){			// verify all certs
			if(!UtilsServer.verifyCert(cert, rootCert)){
				System.out.println("ISSUE verifying certificate");
				System.exit(1);
			}
		}
		i += (4 + sizeCerts);


		/* TODO: move this part up, should be done before, I guess... */

		// Verify hash
		int hashSize = UtilsServer.byteArrToInt(Arrays.copyOfRange(reply, j-4, j));
		j -= 4;
		byte[] buffHash = Arrays.copyOfRange(reply, j-hashSize, j);
		j -= hashSize;
		if(!UtilsServer.verifyHash(Arrays.copyOfRange(reply, 0, j), buffHash, hashFunc)){
			System.out.println("Could not verify hash of Box");
		}

		// Verify signature
		int sigSize = UtilsServer.byteArrToInt(Arrays.copyOfRange(reply, j-4, j));
		j -= 4;
		byte[] sigBox = Arrays.copyOfRange(reply, j-sigSize, j);
		j -= sigSize;
		PublicKey kPubBox = UtilsServer.getSpecificCertificate("RSA", certsBox).getPublicKey();
		if(!UtilsServer.verifySig(initSig, kPubBox, Arrays.copyOfRange(reply, 0, j), sigBox)){
			System.out.println("Could not verify signature of Box");
		}

		// Get algs
        Properties properties = UtilsServer.parserDictionary(cs, "./configs/dictionaryCipherSuites");
		String digSig = properties.getProperty("digital-signature");
		String ecspec = properties.getProperty("ecspec");
		String ciphersuite = properties.getProperty("ciphersuite");
		String keySizeSym = properties.getProperty("key-size-sym");
		String integrity = properties.getProperty("integrity");
		String macKeySize = properties.getProperty("Mackey-size");


		/*--------------------------- Build message ---------------------------*/

		byte[] msg = new byte[] { };

		// send nonce
		msg = UtilsServer.byteArrConcat(msg, UtilsServer.intToByteArr(nonce.length));
		msg = UtilsServer.byteArrConcat(msg, nonce);

		// send ciphersuite
		msg = UtilsServer.byteArrConcat(msg, UtilsServer.intToByteArr(cs.getBytes().length));
		msg = UtilsServer.byteArrConcat(msg, cs.getBytes());

		// Send DH parameters
		byte[] servDHbytes = servPair.getPublic().getEncoded();
		msg = UtilsServer.byteArrConcat(msg, UtilsServer.intToByteArr(servDHbytes.length));
		msg = UtilsServer.byteArrConcat(msg, servDHbytes);

		// Send certificate
		byte[] certByte = UtilsServer.fileToByte(UtilsServer.chooseCertificate(digSig));
		msg = UtilsServer.byteArrConcat(msg, UtilsServer.intToByteArr(certByte.length));
		msg = UtilsServer.byteArrConcat(msg, certByte);

		// Send signature
		PrivateKey kPriv = UtilsServer.readGeneralPrivateKey(digSig);
		byte[] sig = UtilsServer.sign(kPriv, digSig, msg);
		msg = UtilsServer.byteArrConcat(msg, sig);
		msg = UtilsServer.byteArrConcat(msg, UtilsServer.intToByteArr(sig.length));

		// hash
		msg = UtilsServer.byteArrConcat(msg, UtilsServer.getHash(hashFunc, msg));
		msg = UtilsServer.byteArrConcat(msg, UtilsServer.intToByteArr(UtilsServer.getHashLen(hashFunc)));

		// Prepare kmac
		msg = UtilsServer.byteArrConcat(msg, macBox.doFinal(msg));
		msg = UtilsServer.byteArrConcat(msg, UtilsServer.intToByteArr(macBox.getMacLength()));


		UtilsServer.sendTCP(output, msg);

		serverSocket.close();
		UtilsServer.closeTCPConns(socket, input, output);


		/********* BEGIN UDP CONNECTION *********/



	}


}






