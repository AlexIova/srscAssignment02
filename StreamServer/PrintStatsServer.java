import javax.crypto.SecretKey;

class PrintStatsServer {
    
    
        private static void PrintStatsStream(String movie, String csuite, String ks,
                    int ksize, String hic,
                    int nf, int afs, int ms, int etm,
                    int frate, int tput)
        {
    
        System.out.println("---------------------------------------------");
        System.out.println("Streaming Server observed Indicators and Statistics");
        System.out.println("---------------------------------------------");
        System.out.println("Streamed Movie and used Cryptographic Configs");
        System.out.println("---------------------------------------------");
        System.out.println("Movie (streamed):" +movie );
        System.out.println("Used ciphersuite ALG/MODE/PADDING: " +csuite);
        System.out.println("Used Key (hexadecimal rep.): "+ks);
        System.out.println("Used Keysize: " +ksize);
        System.out.println("Used Hash or Mac for integrty checks: " +hic);
        System.out.println();
        System.out.println("---------------------------------------------");
        System.out.println("Performance indicators of streaming" );
        System.out.println("delivered to receiver Box(es)");
        System.out.println("---------------------------------------------");
        System.out.println("Nr of sent frames: " + nf);
        System.out.println("Average frame size: " + afs);
        System.out.println("Movie size sent (all frames): " + ms);
        System.out.println("Total elapsed time of streamed movie: " + etm);
        System.out.println("Average sent frame rate (frames/sec): " +frate);
        System.out.println("Observed troughput (KBytes/sec): " + tput);
    
        }
        
        public static void PrintStream(String movie, String ciphersuite, 
                                    String hcheck, SecretKey keySymm, 
                                    int nf, int ms, int etm){
    
            int afs = ms/nf;
            int frate = nf/(etm/1000);
            int tput = (ms/1000)/(etm/1000);
            String key = UtilsServer.toHex(keySymm.getEncoded());
            int ksize = 4 * key.length();
        
            PrintStatsStream(movie, ciphersuite, key, ksize, hcheck, nf, afs, ms, etm, frate, tput);
            return;
        }


        public static void PrintHandShake(long latency, String kMacInit,  byte[] dhkey, String initSig, int packetSent, int packetRcv){

            System.out.println("Time for sending message and creating keys: " + latency + " ms");
            System.out.println("kMac for initial authenticity " + kMacInit);
            System.out.println("Secret generation from DH: " + UtilsServer.toHex(dhkey));
            System.out.println("Initial algorithm for signature: " + initSig);
            System.out.println("Size of packet received " + packetRcv);
            System.out.println("Size of packet sent " + packetSent);
            

        }


    }
    