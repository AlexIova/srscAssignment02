import javax.crypto.SecretKey;

class PrintStatsBox{
    
        private static void PrintStatsStream(String movie, String csuite, String hic,
                    String ks, int ksize,
                    int nf, int afs, int ms, int etm,
                    int frate, int tput, int asesegments, int asdecsegments, int csegments)
        {
    
            System.out.println("---------------------------------------------");
            System.out.println("BOX Indicators and Statistics");	
            System.out.println("---------------------------------------------");
            System.out.println();
            System.out.println("---------------------------------------------");
            System.out.println("Receved Movie and used Cryptographic Configs");
            System.out.println("---------------------------------------------");
            System.out.println("Received movie (receoved streamed):" +movie );
            System.out.println("Used ciphersuite ALG/MODE/PADDING: " +csuite);
            System.out.println("Used Key (hexadecimal rep.): "+ks);
            System.out.println("Used Keysize: " +ksize);
            System.out.println("Used Hash for integrty checks: " +hic);
    
            System.out.println();	
            System.out.println("---------------------------------------------");
            System.out.println("Performance indicators of received stream" );
            System.out.println("processed delivered to the media player");
            System.out.println("---------------------------------------------");
            System.out.println("avg size of the received encrypted segments: " + asesegments);
            System.out.println("avg size of the decrypted segments: " + asdecsegments);
            System.out.println("Nr of received frames: " + nf);
            System.out.println("Processed average frame size: " + afs);
            System.out.println("Received movie size (all frames): " + ms);
            System.out.println("Total elapsed time of received movie: " + etm);
            System.out.println("Average frame rate (frames/sec): " + frate);
            System.out.println("Box observed troughput (KBytes/sec): " + tput);
            System.out.println("Nr of segments w/ integrity invalidation \n(filtered and not sent to the media player) " + csegments);	
            System.out.println("---------------------------------------------");
    
        }
    
        public static void printStream(String movie, String ciphersuite, String hcheck, SecretKey keySymm, 
                                    int count, int sizeC, int sizeD, int time, int discarded){

            String key = UtilsBox.toHex(keySymm.getEncoded());
            int ksize = 4 * key.length();
            int afs = sizeC/count;
            int frate = count/time;
            int tput = (sizeD/1000)/time;
            int asesegments = sizeC/count;
            int asdecsegments = sizeD/count;
    
            PrintStatsStream(movie, ciphersuite, hcheck, key, ksize, 
                        count, afs, sizeC, time, frate, 
                        tput, asesegments, asdecsegments, discarded);
    
        }



        public static void PrintHandShake(long latency, String kMacInit,  byte[] dhkey, String initSig, int packetSent, int packetRcv){
            
            System.out.println("Time RTT and key generation: " + latency + " ms");
            System.out.println("kMac for initial authenticity " + kMacInit);
            System.out.println("Secret generation from DH: " + UtilsBox.toHex(dhkey));
            System.out.println("Initial algorithm for signature: " + initSig);
            System.out.println("Size of packet received " + packetRcv);
            System.out.println("Size of packet sent " + packetSent);

        }


    }