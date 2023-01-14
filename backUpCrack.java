public class backUpCrack {

    public static void main(String[] args){
        SDES sdesObject = new SDES();
        CASCII casciiObject = new CASCII();

        if (args[0].equals("encrypt")){
            //call Encrypt method
            byte rawKey[] = sdesObject.InputToByteArray(args[1]);
            String text = stringToEncoded(sdesObject, casciiObject, args[2]);
            byte encrypted[] = new byte[text.length()];

            for (int i = 0; i < text.length() / 8; i++){
                int num = i * 8;
                String batch = text.substring(i*8,(i+1)*8);
                byte batchByte[] = sdesObject.InputToByteArray(batch);
                byte eight[] = sdesObject.Encrypt(rawKey, batchByte);
                encrypted[num] = eight[0];
                encrypted[num+1] = eight[1];
                encrypted[num+2] = eight[2];
                encrypted[num+3] = eight[3];
                encrypted[num+4] = eight[4];
                encrypted[num+5] = eight[5];
                encrypted[num+6] = eight[6];
                encrypted[num+7] = eight[7];
            }

            String cipherText = sdesObject.ByteArrayToString(encrypted);
            System.out.println(cipherText);
        } else {

            String keyword = args[1];
            String cipherText = args[2];
            /**
             * split string to array of strings having the length of 8
             *
             * run crack key -->  attempts will be the key 0000000000 through 1111111111
             * call sdesObject.Decrypt(crackKey, cipherText) ---- crackKey 10 bit and cipherText 8 bit
             * Get new bytes and decoded using CASCII
             * Check if it does not contain any
             */

            byte decrypted[] = new byte[cipherText.length()];

            for (int k = 0; k<1024; k++){
                String crackedKey = intToBinaryToString(k);

                for(int j = 0; j < cipherText.length()/8; j++){
                    int num = j * 8;
                    String batch = cipherText.substring(j*8,(j+1)*8);
                    byte batchByte[] = sdesObject.InputToByteArray(batch);
                    byte eight[] = sdesObject.Decrypt(sdesObject.InputToByteArray(crackedKey), batchByte);
                    decrypted[num] = eight[0];
                    decrypted[num+1] = eight[1];
                    decrypted[num+2] = eight[2];
                    decrypted[num+3] = eight[3];
                    decrypted[num+4] = eight[4];
                    decrypted[num+5] = eight[5];
                    decrypted[num+6] = eight[6];
                    decrypted[num+7] = eight[7];
                }

                String realText = casciiObject.toString(decrypted);

                if (realText.contains(keyword)){
                    System.out.println("Cracked Key: " + crackedKey);
                    System.out.println("Message: " + realText);
                    return;
                }






            }
        }
    }

    public static String intToBinaryToString(int count){
        String binary = Integer.toBinaryString(count);
        String results = "";
//        System.out.println(binary.length());

        if (binary.length() < 10 ){
            int zeros = 10 - binary.length();
//            System.out.println("Zeros to be added: " + zeros);
            for (int i = 0; i < zeros; i++){results = results + "0";}
//            System.out.println("Zero results: " + results);
            results = results + binary;
//            System.out.println("Results + Binary: " + results);
        } else {
            return binary;
        }
        return results;
    }
    public static String stringToEncoded(SDES sdesObject, CASCII casciiObject, String text){
        // encode text
        byte textConverted[] = casciiObject.Convert(text);
        // encoded byte array to string
        String results = sdesObject.ByteArrayToString(textConverted);
        return results;
    };



    public static int dictionaryAttack(){


        return 0;
    }

}