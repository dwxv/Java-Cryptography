import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner;

public class CrackingTripleDES {

    public static void main(String[] args) throws FileNotFoundException {
        SDES sdesObject = new SDES();
        TripleDES tripleDESObject = new TripleDES();
        CASCII casciiObject = new CASCII();
        CrackingSDES crackingSDESObject = new CrackingSDES();

        String[] englishDictionary = englishList();


        /**
         * split string to array of strings having the length of 8
         *
         * run crack key -->  attempts will be the key 0000000000 through 1111111111
         * call sdesObject.Decrypt(crackKey, cipherText) ---- crackKey 10 bit and cipherText 8 bit
         * Get new bytes and decoded using CASCII
         * Check if it does not contain any
         */

        if (args[0].equals("encrypt")){
            //call Encrypt method
            byte rawKey1[] = sdesObject.InputToByteArray(args[1]);
            byte rawKey2[] = sdesObject.InputToByteArray(args[2]);
            System.out.println(args[3]);
            String text = CrackingSDES.stringToEncoded(sdesObject, casciiObject, args[3]);
            byte encrypted[] = new byte[text.length()];

            for (int i = 0; i < text.length() / 8; i++){
                int num = i * 8;
                String batch = text.substring(i*8,(i+1)*8);
                byte batchByte[] = sdesObject.InputToByteArray(batch);
                byte eight[] = tripleDESObject.Encrypt(rawKey1, rawKey2, batchByte);
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
        } else {
//            String keyword = args[1];
            String cipherText = args[1];
//            System.out.println(keyword);
//            System.out.println(cipherText);

            int myCountForTesting = 0;
            byte decrypted[] = new byte[cipherText.length()];
            String[] possibleText = new String[1000];
            String[] possibleKey1 = new String[1000];
            String[] possibleKey2 = new String[1000];
            int count = 0;



            for (int k = 0; k<1024; k++){
                String crackedKey1 = crackingSDESObject.intToBinaryToString(k);
                for (int p = 0; p < 1024; p++){
                    String crackedKey2 = crackingSDESObject.intToBinaryToString(p);

                    for(int j = 0; j < cipherText.length()/8; j++){
                        int num = j * 8;
                        String batch = cipherText.substring(j*8,(j+1)*8);
                        byte batchByte[] = sdesObject.InputToByteArray(batch);

                        byte eight[] = tripleDESObject.Decrypt(sdesObject.InputToByteArray(crackedKey1), sdesObject.InputToByteArray(crackedKey2), batchByte);
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


                    String lastChar = realText.substring(realText.length()-1);
                    String firstChar = realText.substring(0,1);
//                    System.out.println("FIRST CHAR " + firstChar);
                    String splitText[] = realText.split("\\s+");
                    String colon = ":";
                    String question = "?";
                    String period = ".";
                    String comma = ",";
                    String apostrophe = "'";
                    String space = " ";
                    String [] punctuation = {":", "?", ".", ",", " ", "'"};

                    int textScore = 0;


                    if (  splitText.length > 4 && !firstChar.contains(colon) && !firstChar.contains(question) && !firstChar.contains(comma) && !firstChar.contains(period) && !firstChar.contains(apostrophe) &&  !firstChar.contains(space)    ){
                        Boolean pass = true;
                        // check if there are double punctuation in realText
                        for(int x = 0; x < punctuation.length; x++){
                            for (int y = 0; y < punctuation.length; y++){
                                String doublePunctuation = punctuation[x] + punctuation[y];
                                if (realText.contains(doublePunctuation)){
                                    pass = false;
                                }
                            }
                        }

                        // check if each split text in real text has the punctuation at the end of it and not any where else
                        // the space and ' is not include in this
                        for (int w = 0; w < splitText.length; w++){
                            int punCheck = splitText[w].length() -1;
                            for (int u = 0; u < punctuation.length-2; u++){
                                if(splitText[w].contains(punctuation[u]) &&  !splitText[w].substring(punCheck).equals(punctuation[u]) ){
                                    pass = false;
                                }
                            }

                        }

                        if (pass){
//                          textScore = dictionaryAttack(englishDictionary, realText);
                            System.out.println("Key1: " + crackedKey1 + " Key2: " + crackedKey2 + " text: " + realText);
                            myCountForTesting++;
                        }

                    }
//                    int textScore = dictionaryAttack(englishDictionary, realText);
//                    if (splitText.length > 3){
//                        textScore = dictionaryAttack(englishDictionary, realText);
//                    }

                    if (textScore > 3){
//                    System.out.println("textScore: " + textScore);
                    System.out.println("Crack Key1: " + crackedKey1);
                    System.out.println("Crack Key2: " + crackedKey2);
                    System.out.println("Plaintext: " + realText);
                        count++;
                        return;
                    }
                }
            }

            // print out possible keys:
            if (count > 0){
                // for loop to get keys
                System.out.println("\nPossible Result(s)");
                for (int f = 0; f < count; f++){
                    System.out.println("Cracked Key1: " + possibleKey1[f] + "\nCracked Key2: " + possibleKey2[f] + "\nMessage: " + possibleText[f]);
                }
            } else {
                // no key was found
                System.out.println(myCountForTesting);
                System.out.println("No Key Was Found.");
            }
        }
    }


    public static String[] englishList() throws FileNotFoundException {

        File file = new File("./english.txt");
        Scanner scan = new Scanner(file);

        String[] list = new String[42911];
        int count = 0;
        while (scan.hasNextLine()) {
            list[count] = scan.nextLine();
            count++;
        }
        return list;
    }


    public static int dictionaryAttack(String[] list, String s){
        int value = 0;
        String[] sSplit = s.split("\\s+");
        String sFirstWord = sSplit[0];
        String sLastWord = sSplit[sSplit.length - 1];
//        System.out.println("First:" + sFirstWord+"------");
//        System.out.println("Last:" + sLastWord+"------");




        for (int i = 0; i < list.length; i++){
            String word = list[i];
            if (word != null){
                String WORD = " " +  word.toUpperCase() + " "; // checks any word that isn't the first or last
                String flWORD =  word.toUpperCase(); // checks any word that isn't the first or last
                String lWORD = " " +  word.toUpperCase() ; // checks any word that isn't the first or last

                if (s.contains(WORD)){
//                    System.out.println(WORD);
//                    System.out.println("contains");
                    value++;
//                    System.out.println("Value " + value);
                } else if ( (sFirstWord.equals(flWORD) || sLastWord.equals(flWORD)) && sSplit.length > 1 ){
//                    System.out.println(WORD);
//                    System.out.println("contains");
                    value++;
//                    System.out.println("Value " + value);

                }

            }
        }
//        System.out.println(value);
        return value;
    }


}




//Desktop/CSULA/CSULA Fall 2021/cs4780 Cryptography/4780_Project1_Group5/src