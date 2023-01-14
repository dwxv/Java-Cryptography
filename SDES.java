//Raw Key       Plaintext           Ciphertext
//0000000000     10101010            00010001
//1110001110     10101010            11001010
//1110001110     01010101            01110000
//1111111111     10101010            00000100

// rawkey 1110001110
// p10

import java.lang.reflect.Array;

public class SDES {
    public static void main(String[] args) {
        if (!Validation(args)){return;}
        byte rawKey[] = InputToByteArray(args[1]);
        byte text[] = InputToByteArray(args[2]);

        if (args[0].equals("encrypt")){
            //call Encrypt method
            byte cipherTextArray[] = Encrypt(rawKey, text);
            String cipherText = ByteArrayToString(cipherTextArray);
            System.out.println(cipherText);
        } else {
            //call Decrypt method
            byte plainTextArray[] = Decrypt(rawKey, text);
            String plainText = ByteArrayToString(plainTextArray);
            System.out.println(plainText);
        }

    }

    @SuppressWarnings("DuplicatedCode")
    public static byte[] Encrypt(byte[] rawkey, byte[] text){

        // Generate KEYS:
        byte p10[] = P10(rawkey);
        byte LS1[] = LeftShift(1, p10);
        byte k1[] = P8(LS1);
        byte LS2[] = LeftShift(2, LS1);
        byte k2[] = P8(LS2);
//        System.out.println("rawkey: " + rawkey[0] + "" + rawkey[1]+ "" +  rawkey[2]+ "" +  rawkey[3]+ "" +  rawkey[4]+ "" +  rawkey[5]+ "" +  rawkey[6]+ "" + rawkey[7]+ "" +  rawkey[8]+ "" +  rawkey[9]);
//        System.out.println("p10---: " + rawkey[3-1] + "" + rawkey[5-1]+ "" +  rawkey[2-1]+ "" +  rawkey[7-1]+ "" +  rawkey[4-1]+ "" +  rawkey[10-1]+ "" +  rawkey[1-1]+ "" + rawkey[9-1]+ "" +  rawkey[8-1]+ "" +  rawkey[6-1]);
//        System.out.println("LS1---: " + LS1[0] + "" + LS1[1]+ "" +  LS1[2]+ "" +  LS1[3]+ "" +  LS1[4]+ "" +  LS1[5]+ "" +  LS1[6]+ "" + LS1[7]+ "" +  LS1[8]+ "" +  LS1[9]);
//        System.out.println("k1----: " + k1[0] + "" + k1[1]+ "" +  k1[2]+ "" +  k1[3]+ "" +  k1[4]+ "" +  k1[5]+ "" +  k1[6]+ "" + k1[7]);
//        System.out.println("LS2---: " + LS2[0] + "" + LS2[1]+ "" +  LS2[2]+ "" +  LS2[3]+ "" +  LS2[4]+ "" +  LS2[5]+ "" +  LS2[6]+ "" + LS2[7]+ "" +  LS2[8]+ "" +  LS2[9]);
//        System.out.println("k2----: " + k2[0] + "" + k2[1]+ "" +  k2[2]+ "" +  k2[3]+ "" +  k2[4]+ "" +  k2[5]+ "" +  k2[6]+ "" + k2[7]);
        //https://www.youtube.com/watch?v=3jGMCyOXOV8&t=194s 24:36

        // Encryption:
        byte ip[] = {text[2-1], text[6-1], text[3-1], text[1-1], text[4-1], text[8-1], text[5-1], text[7-1] };
        byte ipLhs[] = {ip[0],ip[1],ip[2],ip[3]};
        byte ipRhs[] = {ip[4],ip[5],ip[6],ip[7]};
        //fk1
        byte ep[] = EP(ipRhs,k1);
        byte p4[] = P4(ep);
        byte ipLHSXorP4[] = XOR(ipLhs, p4);
        // end of fk1
        byte swap[] = Swap4to8(ipRhs, ipLHSXorP4);

        //fk2:
        byte swapLhs[] = {swap[0], swap[1], swap[2], swap[3] };
        byte swapRhs[] = {swap[4],swap[5],swap[6],swap[7]};
        byte epSwap[] = EP(swapRhs,k2);
        byte p4Swap[] = P4(epSwap);
        byte ipLHSXorP4Swap[] = XOR(swapLhs, p4Swap);
        byte cipherText[] = PI(ipLHSXorP4Swap, swapRhs);




//        System.out.println("");
//        System.out.println("text---: " + text[0] + "" + text[1]+ "" +  text[2]+ "" +  text[3]+ "" +  text[4]+ "" +  text[5]+ "" +  text[6]+ "" + text[7]);
//        System.out.println("ip-----: " + ip[0] + "" + ip[1]+ "" +  ip[2]+ "" +  ip[3]+ "" +  ip[4]+ "" +  ip[5]+ "" +  ip[6]+ "" + ip[7]);
//        System.out.println("ep-----: " + ep[0] + "" + ep[1]+ "" +  ep[2]+ "" +  ep[3]);
//        System.out.println("p4-----: " + p4[0] + "" + p4[1]+ "" +  p4[2]+ "" +  p4[3]);
//        System.out.println("ipLHSP4: " + ipLHSXorP4[0] + "" + ipLHSXorP4[1]+ "" +  ipLHSXorP4[2]+ "" +  ipLHSXorP4[3]);
//        System.out.println("swap---: " + swap[0] + "" + swap[1]+ "" +  swap[2]+ "" +  swap[3]+ "" +  swap[4]+ "" +  swap[5]+ "" +  swap[6]+ "" + swap[7]);
//        System.out.println("cipherT: " + cipherText[0] + "" + cipherText[1]+ "" +  cipherText[2]+ "" +  cipherText[3]+ "" +  cipherText[4]+ "" +  cipherText[5]+ "" +  cipherText[6]+ "" + cipherText[7]);
//        System.out.println("cipherText should be 0111 0111");

        return cipherText;
    };

    public static byte[] Decrypt(byte[] rawkey, byte[] ciphertext){

        // Generate KEYS:
        byte p10[] = P10(rawkey);
        byte LS1[] = LeftShift(1, p10);
        byte k1[] = P8(LS1);
        byte LS2[] = LeftShift(2, LS1);
        byte k2[] = P8(LS2);


        // Decryption:
        //ip^-1 ---> back to IP
        byte ip[] =IP(ciphertext);
        byte ipLhs[] = {ip[0],ip[1],ip[2],ip[3]};
        byte ipRhs[] = {ip[4],ip[5],ip[6],ip[7]};

        byte ep[] = EP(ipRhs,k2);
        byte p4[] = P4(ep);
        byte ipLHSXorP4[] = XOR(ipLhs, p4);
        // end of fk2
        byte swap[] = Swap4to8(ipRhs, ipLHSXorP4);

        //fk1:
        byte swapLhs[] = {swap[0], swap[1], swap[2], swap[3] };
        byte swapRhs[] = {swap[4],swap[5],swap[6],swap[7]};
        byte epSwap[] = EP(swapRhs,k1);
        byte p4Swap[] = P4(epSwap);
        byte ipLHSXorP4Swap[] = XOR(swapLhs, p4Swap);
        byte plainText[] = PI(ipLHSXorP4Swap, swapRhs);


        return plainText;
    };

    public static byte[] P10(byte[] rawkey){
        //P10(k1, k2, k3, k4, k5, k6, k7,k8, k9, k10) = (k3, k5, k2, k7, k4, k10, k1, k9, k8, k6)
        // rawkey[num-1] --> -1 because index is at 0; if we don't do this index 10 (k10) is out of bounds
        byte results[] = {rawkey[3-1], rawkey[5-1],  rawkey[2-1],  rawkey[7-1],  rawkey[4-1],  rawkey[10-1],  rawkey[1-1],  rawkey[9-1],  rawkey[8-1],  rawkey[6-1]};
        return results;
    };
    public static byte[] LeftShift(int shiftAmount, byte[] arr){
        byte ls1[] = new byte[5];
        byte ls2[] = new byte[5];

        for (int i = 0; i < arr.length; i++){
            if (i < 5){
                ls1[i] = arr[i];
            } else {
                ls2[i-5] = arr[i];
            }
        }

        if (shiftAmount == 1){
            byte ls1First = ls1[0];
            byte ls2First = ls2[0];

            for (int p = 1; p < 5; p++){
                ls1[p-1] = ls1[p];
                ls2[p-1] = ls2[p];
            }
            ls1[4] = ls1First;
            ls2[4] = ls2First;

            return MergeArrays(ls1, ls2);

        } else {
            byte ls1First = ls1[0];
            byte ls1Second = ls1[1];
            byte ls2First = ls2[0];
            byte ls2Second = ls2[1];

            for (int p = 2; p < 5; p++){
                ls1[p-2] = ls1[p];
                ls2[p-2] = ls2[p];
            }

            ls1[3] = ls1First;
            ls1[4] = ls1Second;
            ls2[3] = ls2First;
            ls2[4] = ls2Second;

            return MergeArrays(ls1, ls2);
        }
    };
    public static byte[] P8(byte[] key){
        byte results[] = {key[6-1], key[3-1], key[7-1], key[4-1], key[8-1], key[5-1], key[10-1], key[9-1] };
        return results;
    };
    public static byte[] EP(byte[] rhs, byte[] k){
        // 4 1 2 3 2 3 4 1
        byte expand[] = {rhs[4-1], rhs[1-1], rhs[2-1], rhs[3-1], rhs[2-1], rhs[3-1], rhs[4-1], rhs[1-1] };
        return Substitution(expand, k);
    };
    public static byte[] XOR(byte[] arr1, byte[] arr2){
        byte results[] = new byte[arr1.length + arr2.length];

        for (int i = 0; i < arr1.length; i++){
            if (arr1[i] == arr2[i]){
                results[i] = 0;
            } else {
                results[i] = 1;
            }
        }
        return results;
    };
    public static byte[] Substitution(byte[] ep, byte[] k1){
        byte subs[] = XOR(ep, k1);

        byte lhs[] = {subs[0], subs[1], subs[2], subs[3] };
        byte rhs[] = {subs[4], subs[5], subs[6], subs[7] };

        byte s0[] = SBox(0, lhs);
        byte s1[] = SBox(1, rhs);
        byte mergedS1S2[] = MergeArrays(s0, s1);

//        System.out.println("sub---: " + subs[0] + "" + subs[1]+ "" +  subs[2]+ "" +  subs[3]+ "" +  subs[4]+ "" +  subs[5]+ "" +  subs[6]+ "" + subs[7]);
        return mergedS1S2;
    };
    public static byte[] SBox(int box, byte[] arr){
        byte results[] = new byte[2];
        String row = String.valueOf(arr[0]) + String.valueOf(arr[3]);
        String col = String.valueOf(arr[1]) + String.valueOf(arr[2]);
        int rowInt = Integer.parseInt(row, 2);
        int colInt = Integer.parseInt(col, 2);
        byte s0[][] = {{01, 00, 11, 10}, {11, 10, 01, 00}, {00, 10, 01, 11}, {11, 01, 11, 10}};
        byte s1[][] = {{00, 01, 10, 11}, {10, 00, 01, 11}, {11, 00, 01, 00}, {10, 01, 00, 11}};
        int bitOutput = s0[rowInt][colInt];

        if (box != 0){
            bitOutput = s1[rowInt][colInt];
        }

        if (String.valueOf(bitOutput).length() == 1){
            results[0] = 0;
            results[1] = (byte) bitOutput;
        } else {
            results[0] = (byte) (bitOutput/10);
            results[1] = (byte) (bitOutput%10);
        }

        return results;
    };
    public static byte[] P4(byte[] arr){
        byte results[] ={arr[2-1], arr[4-1], arr[3-1], arr[1-1] };
        return results;
    };
    public static byte[] Swap4to8(byte[] arr1, byte[] arr2){
        byte results[] = {arr1[0], arr1[1], arr1[2], arr1[3], arr2[0], arr2[1], arr2[2], arr2[3] };
        return results;
    };
    public static byte[] PI(byte[] arr1, byte[] arr2){
        //41357286
        byte arr3[] = {arr1[0], arr1[1], arr1[2], arr1[3], arr2[0], arr2[1], arr2[2], arr2[3] };
        byte results[] = {arr3[4-1], arr3[1-1], arr3[3-1], arr3[5-1], arr3[7-1], arr3[2-1], arr3[8-1], arr3[6-1] };
//        System.out.println("arr3: " + arr3[0] + "" + arr3[1]+ "" +  arr3[2]+ "" +  arr3[3]+ "" +  arr3[4]+ "" +  arr3[5]+ "" +  arr3[6]+ "" + arr3[7]);
//        System.out.println("results: " + results[0] + "" + results[1]+ "" +  results[2]+ "" +  results[3]+ "" +  results[4]+ "" +  results[5]+ "" +  results[6]+ "" + results[7]);
        return results;
    };
    public static byte[] IP(byte[] arr){
        // 26314857
        byte results[] = {arr[2-1], arr[6-1], arr[3-1], arr[1-1], arr[4-1], arr[8-1], arr[5-1], arr[7-1] };
        return results;
    };




    // Helper methods:
    public static boolean Validation(String[] args){
        // Validation: args[0] length 3;
        // encrypt/decrypt first arg;
        // second args[1] 10 bytes raw key;
        // third args[2] 8 bytes plaintext or ciphertext
        if (args.length < 3){
            System.out.println("Invalid Format. encrypt/decrypt RawKey Plaintext/CipherText");
            return false;
        };
        if (!args[0].equals("encrypt") && !args[0].equals("decrypt")){
            System.out.println("Invalid Format (argument 1). Must enter encrypt or decrypt for the first argument");
            return false;
        }
        if (args[1].length() != 10){
            System.out.println("Invalid Format (argument 2). Raw Key needs to be 10 bytes");
            return false;
        }
        if (args[2].length() != 8){
            System.out.println("Invalid Format (argument 3). Plaintext or Ciphertext needs to be 8 bytes");
            return false;
        }
        return true;
    };
    public static byte[] InputToByteArray(String input){
        byte array[] = new byte[input.length()];
        for (int i = 0; i < input.length(); i++){
            char c = input.charAt(i);
            int n = Integer.parseInt(String.valueOf(c));
            array[i] = (byte) n;
        }
        return array;
    };
    public static String ByteArrayToString(byte[] arr){
        String s = "";

        for (int i = 0; i < arr.length; i++){
            int n = arr[i];
            s += String.valueOf(n);
        }
        return s;
    };
    public static byte[] MergeArrays(byte[] arr1, byte[] arr2){
        int len = arr1.length + arr2.length;
        int half = Math.floorDiv(len, 2);
//        int half = 0;
//        if (len%2 == 0){
//            half = len/2 - 1;
//        } else {
//            half = len/2;
//        }
        byte results[] = new byte[len];

        for(int q = 0; q < len; q++){
            if (q<half){
                results[q] = arr1[q];
            } else {
                results[q] = arr2[q-half];
            }
        }
        return results;
    }
}










