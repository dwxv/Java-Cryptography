//public class TripleDES {
//    public static void main(String[] args) {
//        if (!Validation(args)){
//            return;
//        }
//        SDES sdesObject = new SDES();
//        String job = args[0];
//        byte rawKey1[] = sdesObject.InputToByteArray(args[1]);
//        byte rawKey2[] = sdesObject.InputToByteArray(args[2]);
//        byte text[] = sdesObject.InputToByteArray(args[3]);
//
//        // E3DES(p) = EDES(k1,DDES(k2,EDES(k1, p)))
//        // D3DES(c) = DDES(k1,EDES(k2,DDES(k1, c))
//        // since the encryption uses rawkey1-->rawkey2-->rawkey1
//        // the decryption uses is in reverse rawkey1<--rawkey2<--rawkey1
//        // if there was three keys decryption would be rawkey3-->rawkey2-->rawkey1
//        // the code below will be the same for encryption and decryption for this problem
//        if (job.equals("encrypt")){
//            byte firstRound[] = sdesObject.Encrypt(rawKey1, text);
//            byte secondRound[] = sdesObject.Encrypt(rawKey2, firstRound);
//            byte thirdRound[] = sdesObject.Encrypt(rawKey1, secondRound);
//            String resultText = sdesObject.ByteArrayToString(thirdRound);
//            System.out.println(resultText);
//        } else {
//            byte firstRound[] = sdesObject.Decrypt(rawKey1, text);
//            byte secondRound[] = sdesObject.Decrypt(rawKey2, firstRound);
//            byte thirdRound[] = sdesObject.Decrypt(rawKey1, secondRound);
//            String resultText = sdesObject.ByteArrayToString(thirdRound);
//            System.out.println(resultText);
//        }
//    }
//
//    // Helper methods:
//    public static boolean Validation(String[] args){
//        // Validation: args[0] length 3;
//        // encrypt/decrypt first arg;
//        // second args[1] 10 bytes raw key;
//        // third args[2] 8 bytes plaintext or ciphertext
//        if (args.length < 4){
//            System.out.println("Invalid Format. encrypt/decrypt RawKey Plaintext/CipherText");
//            return false;
//        };
//        if (!args[0].equals("encrypt") && !args[0].equals("decrypt")){
//            System.out.println("Invalid Format (argument 1). Must enter encrypt or decrypt for the first argument");
//            return false;
//        }
//        if (args[1].length() != 10){
//            System.out.println("Invalid Format (argument 2). Raw Key 1 needs to be 10 bytes");
//            return false;
//        }
//        if (args[2].length() != 10){
//            System.out.println("Invalid Format (argument 3). Raw Key 2 needs to be 10 bytes");
//            return false;
//        }
//        if (args[3].length() != 8){
//            System.out.println("Invalid Format (argument 4). Plaintext or Ciphertext needs to be 8 bytes");
//            return false;
//        }
//        return true;
//    };
//
//}
//// key1: 1000101110
//// Key2: 0110101110
//// Text: 10101010
//// Ciph: 10011110


public class TripleDES {
    public static void main(String[] args) {
      if (!Validation(args)){
          return;
      }
        SDES sdesObject = new SDES();
        String job = args[0];
        byte rawKey1[] = sdesObject.InputToByteArray(args[1]);
        byte rawKey2[] = sdesObject.InputToByteArray(args[2]);
        byte text[] = sdesObject.InputToByteArray(args[3]);

        if (args[0].equals("encrypt")){
            byte encrypted[] = Encrypt(rawKey1, rawKey2, text);
            String resultText = sdesObject.ByteArrayToString(encrypted);
            System.out.println(resultText);
        } else {
            byte decrypted[] = Decrypt(rawKey1, rawKey2, text);
            String resultText = sdesObject.ByteArrayToString(decrypted);
            System.out.println(resultText);
        }

    }

    public static byte[] Encrypt(byte[] rawkey1, byte[] rawkey2, byte[] text){
        SDES sdesObject = new SDES();
        // E3DES(p) = EDES(k1,DDES(k2,EDES(k1, p)))
        // since the encryption uses rawkey1-->rawkey2-->rawkey1
        // the decryption uses is in reverse rawkey1<--rawkey2<--rawkey1
        // if there was three keys decryption would be rawkey3-->rawkey2-->rawkey1
        // Encrypt --> Decrypt --> Encrypt
        byte firstRound[] = sdesObject.Encrypt(rawkey1, text);
        byte secondRound[] = sdesObject.Decrypt(rawkey2, firstRound);
        byte thirdRound[] = sdesObject.Encrypt(rawkey1, secondRound);

        return thirdRound;
    }
    public static byte[] Decrypt(byte[] rawkey1, byte[] rawkey2, byte[] ciphertext){
        SDES sdesObject = new SDES();
        // D3DES(c) = DDES(k1,EDES(k2,DDES(k1, c))
        // since the encryption uses rawkey1-->rawkey2-->rawkey1
        // the decryption uses is in reverse rawkey1<--rawkey2<--rawkey1
        // if there was three keys decryption would be rawkey3-->rawkey2-->rawkey1
        // Decrypt --> Encrypt --> Decrypt
        
        
        //second raw key will always be the middle
        
        byte firstRound[] = sdesObject.Decrypt(rawkey1, ciphertext);
        byte secondRound[] = sdesObject.Encrypt(rawkey2, firstRound);
        byte thirdRound[] = sdesObject.Decrypt(rawkey1, secondRound);

        return thirdRound;
    }

    // Helper methods:
    public static boolean Validation(String[] args){
        // Validation: args[0] length 3;
        // encrypt/decrypt first arg;
        // second args[1] 10 bytes raw key;
        // third args[2] 8 bytes plaintext or ciphertext
        if (args.length < 4){
            System.out.println("Invalid Format. encrypt/decrypt RawKey Plaintext/CipherText");
            return false;
        };
        if (!args[0].equals("encrypt") && !args[0].equals("decrypt")){
            System.out.println("Invalid Format (argument 1). Must enter encrypt or decrypt for the first argument");
            return false;
        }
        if (args[1].length() != 10){
            System.out.println("Invalid Format (argument 2). Raw Key 1 needs to be 10 bytes");
            return false;
        }
        if (args[2].length() != 10){
            System.out.println("Invalid Format (argument 3). Raw Key 2 needs to be 10 bytes");
            return false;
        }
        if (args[3].length() != 8){
            System.out.println("Invalid Format (argument 4). Plaintext or Ciphertext needs to be 8 bytes");
            return false;
        }
        return true;
    };


}
