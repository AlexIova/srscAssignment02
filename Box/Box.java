import java.io.*;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.Properties;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.cert.*;

class Box {    
    
    public static void main(String[] args) throws Exception {

		if (args.length != 3)
		{
			System.out.println ("Use: Box <movie> <address> <port>");
			System.exit(-1);
		}

		int BUFF_SIZE = 8192;

		Socket socket = UtilsBox.createTCPSock(args[1], Integer.parseInt(args[2]));
		ObjectOutputStream output = UtilsBox.outTCPStream(socket);
		ObjectInputStream input = UtilsBox.inTCPStream(socket);

		byte[] nonce = UtilsBox.getNonceBytes();

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
		msg = UtilsBox.byteArrConcat(msg, boxDHbytes);
		msg = UtilsBox.byteArrConcat(msg, UtilsBox.intToByteArr(sizeParamDH));

		// certificates
		byte[] certByte = UtilsBox.fileToByte("./certificates/allBoxCerts.crt");
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

		/* Send message */
		UtilsBox.sendTCP(output, msg);


		/******************** Receive reply ********************/

		
		byte[] reply = (byte[]) UtilsBox.recvTCP(input);

		int i = 0;					// Pointer from left
		int j = reply.length;		// Pointer from right

		/* Get kmac */
		int sizeKmac = UtilsBox.byteArrToInt(Arrays.copyOfRange(reply, reply.length-4, reply.length));
		byte[] buffKmacRCV = Arrays.copyOfRange(reply, reply.length-4-sizeKmac, reply.length-4);	// kmac received
		byte[] buffZRcv = Arrays.copyOfRange(reply, 0, reply.length-4-sizeKmac);	// Z of message received
		byte[] buffKmacOWN = macBox.doFinal(buffZRcv);		// Z kmac own calculated
		if( !MessageDigest.isEqual(buffKmacRCV, buffKmacOWN) ){
			System.out.println("Problem validating message SS");
		}
		j = j - sizeKmac - 4;		// size of kmac and size of int

		// Get nonce
		int sizeNonceReply = UtilsBox.byteArrToInt(Arrays.copyOfRange(reply, 0, 4));
		byte[] nonceReply = Arrays.copyOfRange(reply, 4, 4 + sizeNonceReply);
		if (!Arrays.equals(nonce, nonceReply)){
			System.out.println("Nonce does not correspond");
		}
		i += 4 + sizeNonceReply;

		// get CS to use
		int sizeCipherSuite = UtilsBox.byteArrToInt(Arrays.copyOfRange(reply, i, i+4));
		i += 4;
		String cs = UtilsBox.byteToString(Arrays.copyOfRange(reply, i, i+sizeCipherSuite));
		i += sizeCipherSuite;

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
        // KeyPair servPair = boxKpairGen.generateKeyPair();
		boxKeyAgree.doPhase(servDHkeyPub, true);
		// System.out.println(UtilsBox.toHex(boxKeyAgree.generateSecret()));

		// Get certificates
		int sizeCerts = UtilsBox.byteArrToInt(Arrays.copyOfRange(reply, i, i+4));
		X509Certificate rootCert = UtilsBox.getCertificate("./certificates/RootCA.crt");
		X509Certificate certStreamServer = UtilsBox.getCertificateFromBytes(Arrays.copyOfRange(reply, i+4, sizeCerts+i+4));
		if(!UtilsBox.verifyCert(certStreamServer, rootCert)){
			System.out.println("ISSUE verifying certificate");
		}

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

		int portRecvUDP = socket.getLocalPort();		// Server will reply on this port
		System.out.println("port udp: " + portRecvUDP);
		UtilsBox.closeTCPConns(socket, input, output);


		/********* GET CS DATA *********/

		System.out.println("digsig: " + digSig);
		System.out.println("ecscpec: " + ecspec);
		System.out.println("ciphersuites: " + ciphersuite);
		System.out.println("keySizeSym " + keySizeSym);
		System.out.println("integrity " + integrity);
		System.out.println("macKeySize " + macKeySize);

		byte[] DHsecret = boxKeyAgree.generateSecret();
		byte[] byteSimm = Arrays.copyOfRange(DHsecret, 0, 127);
		IvParameterSpec iv = UtilsBox.getAnotherIV(DHsecret, 0);
		
		byteSimm = UtilsBox.hashToKey(byteSimm, Integer.parseInt(keySizeSym));
		
		SecretKey macKey = null;
		MessageDigest hfun = null;
		Mac macF = null;
		if(!macKeySize.equals("NULL")){
			byte[] byteKMac = Arrays.copyOfRange(DHsecret, 128, 256);
			byteKMac = UtilsBox.hashToKey(byteSimm, Integer.parseInt(macKeySize));
			macKey = new SecretKeySpec(byteKMac, integrity);
			macF = UtilsBox.prepareMacFunc(integrity, macKey);
		} else {
			hfun = MessageDigest.getInstance(integrity, "BC");
		}
		SecretKey kSimm = new SecretKeySpec(byteSimm, ciphersuite);

		Cipher symEnc = UtilsBox.prepareSymEnc(ciphersuite, kSimm, iv);
		Cipher symDec = UtilsBox.prepareSymDec(ciphersuite, kSimm, iv);

		kPriv = UtilsBox.readGeneralPrivateKey(digSig);

		System.out.println("secret ksmim: " + UtilsBox.toHex(kSimm.getEncoded()));

		/********* BEGIN UDP CONNECTION *********/

		Properties propAddr = new Properties();
		propAddr.load(new FileInputStream(new File("./configs/address.properties")));

		String hostPlayer = propAddr.getProperty("host");
		int portPlayer = Integer.parseInt(propAddr.getProperty("port"));

		System.out.println("hostPlayer: " + hostPlayer);
		System.out.println("portPlayer: " + portPlayer);

		byte[] buffer = new byte[BUFF_SIZE * 3];
		DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
		byte[] data = null;
		byte[] buffDec = null;

		/* START */
		DatagramSocket sSendUDP = new DatagramSocket();
		DatagramSocket sRecvUDP = new DatagramSocket(portRecvUDP);

		// send movie name to server
		byte[] startMsg = null;
		if(!macKeySize.equals("NULL")){
			startMsg = UtilsBox.preparePacketMac(args[0].getBytes(), symEnc, kPriv, digSig, macF);
		} else {
			startMsg = UtilsBox.preparePacketHash(args[0].getBytes(), symEnc, kPriv, digSig, hfun);
		}
		UtilsBox.sendUDP(sSendUDP, startMsg, args[1], Integer.parseInt(args[2]));
		
		int seqRCV;
		while(true){

			if(UtilsBox.isFinished(inPacket)){
				System.out.println("RILEVATA FINE");
				break;
			}
			sRecvUDP.receive(inPacket);
			data = Arrays.copyOfRange(inPacket.getData(), 0, inPacket.getLength());
			if(macKeySize.equals("NULL")){
				if(UtilsBox.isGCM(ciphersuite)){
					seqRCV = UtilsBox.getSeqHash(data, hfun);
					iv = UtilsBox.getAnotherIV(DHsecret, seqRCV);
					symDec = UtilsBox.prepareSymDec(ciphersuite, kSimm, iv);
				}
				buffDec = UtilsBox.verifyHASHAndDecrypt(data, symDec, kPubBox, digSig, hfun);
			}
			else {
				if(UtilsBox.isGCM(ciphersuite)){
					seqRCV = UtilsBox.getSeqHash(data, hfun);
					iv = UtilsBox.getAnotherIV(DHsecret, seqRCV);
					symDec = UtilsBox.prepareSymDec(ciphersuite, kSimm, iv);
				}
				buffDec = UtilsBox.verifyMACAndDecrypt(data, symDec, kPubBox, digSig, macF);
			}
			UtilsBox.sendUDP(sSendUDP, buffDec, hostPlayer, portPlayer);
			System.out.print(".");

		}
		
		sRecvUDP.close();

	}
	
}

	

