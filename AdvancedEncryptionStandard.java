import java.util.Arrays;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AdvancedEncryptionStandard{
    public static void main(String[] args) throws NoSuchAlgorithmException{
        /*
        int[] exampleState = {0x32, 0x88, 0x31, 0xe0, 0x43, 0x5a, 0x31, 0x37, 0xf6, 0x30, 0x98, 0x07, 0xa8, 0x8d, 0xa2, 0x34};
        int[] exampleRoundKey = {0x2b, 0x28, 0xab, 0x09, 0x7e, 0xae, 0xf7, 0xcf, 0x15, 0xd2, 0x15, 0x4f, 0x16, 0xa6, 0x88, 0x3c};

        int[] newState = addRoundKey(exampleState, exampleRoundKey);
        System.out.println("State after AddRoundKey:");

        for (int val : newState){
            System.out.print(String.format("%02x ", val));
        }
        System.out.println();

        subBytes(newState);
        System.out.println("State after SubBytes:");

        for (int val : newState){
            System.out.print(String.format("%02x ", val));
        }
        System.out.println();

        int[] readableState = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        System.out.println("Readable state after shiftRows: ");
        System.out.println(Arrays.toString(shiftRows(readableState)));
        */

        int[] key = generateKey();
        System.out.println("Random Key: " + Arrays.toString(key));

        //TEMPORARY:::
        key = new int[32];
        for (int i = 0; i < 32; i++){
            key[i] = i+1;
        }

        System.out.println("Temp easy key: " + Arrays.toString(key));

        int[][] keySchedule = keyExpansion(key);
        System.out.println("keySchedule: ");
        for (int i = 0; i < keySchedule.length; i++){
            System.out.println(Arrays.toString(keySchedule[i]));
        }

        String plaintxt = "Hello World !!!!";
        int[] testState = new int[16];
        for (int i = 0; i < 16; i++){
            testState[i] = (int) plaintxt.charAt(i);
        }
        int[] encrypted = cipher(testState, 14, keySchedule);

        String ciphertxt = "";
        for (int i = 0; i < 16; i++){
            ciphertxt += (char) encrypted[i];
        }

        System.out.println("Cipher text: " + ciphertxt);
    }

    public static final int[] sBox = { // better as a one dimensional array
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    };

    public static final int[][] rCon = {
        {0x01, 0x00, 0x00, 0x00}, 
        {0x02, 0x00, 0x00, 0x00}, 
        {0x04, 0x00, 0x00, 0x00}, 
        {0x08, 0x00, 0x00, 0x00}, 
        {0x10, 0x00, 0x00, 0x00}, 
        {0x20, 0x00, 0x00, 0x00}, 
        {0x40, 0x00, 0x00, 0x00}, 
        {0x80, 0x00, 0x00, 0x00}, 
        {0x1b, 0x00, 0x00, 0x00}, 
        {0x36, 0x00, 0x00, 0x00}
    };

    //ENCRYPTION METHODS
    public static int[] addRoundKey(int[] state, int[] roundKey){
        for (int i = 0; i < state.length; i++){
            state[i] ^= roundKey[i];
        }
        return state;
    }

    public static int[] subBytes(int[] state){
        for (int i = 0; i < state.length; i++){
            state[i] = sBox[state[i]];
        }
        return state;
    }

    public static int[] shiftRows(int[] state){
        int[] shiftedState = new int[16];

        for (int i = 0; i < 16; i++){
            int row = i/4;
            int column = i%4;

            shiftedState[i] = state[i + (row - 4 * ((row+column)/4))];
        }

        return shiftedState;
    }

    public static int[] mixColumns(int[] state){
        int[] mixedState = new int[16];
        int[] column = new int[4]; //keeping track of columns
        
        for (int col = 0; col < 4; col++){ 
            for (int row = 0; row < 4; row++){ 
                // simplify getting column/row
                column[row] = state[row * 4 + col];
            }
            //for every column:
            //col 1 = row1 x 2, row2 x 3, the rest multiply by 1 and stay the same, etc
            mixedState[col] = mult(column[0], 2) ^ mult(column[1], 3) ^ column[2] ^ column[3];
            mixedState[col + 4] = column[0] ^ mult(column[1], 2) ^ mult(column[2], 3) ^ column[3];
            mixedState[col + 8] = column[0] ^ column[1] ^ mult(column[2], 2) ^ mult(column[3], 3);
            mixedState[col + 12] = mult(column[0], 3) ^ column[1] ^ column[2] ^ mult(column[3], 2);
        }

        return mixedState;
    }
    
    public static int mult(int a, int b){
        int product = 0;
        int hiBitSet;

        for (int counter = 0; counter < 8; counter++){
           
            if ((b & 1) != 0){
            
                product ^= a;
            }

            hiBitSet = (a & 0x80);
            a <<= 1; //pad with zeroes
           
            if (hiBitSet != 0){
                a ^= 0x1b; 
            }

            b >>= 1; 
        }
        return product;
    }

    public static int[] rotWord(int[] word){
        int[] rotated = new int[4];
        for (int i = 0; i < 3; i++){
            rotated[i] = word[i + 1];
        }
        rotated[3] = word[0];
        return rotated;
    }

    public static int[][] keyExpansion(int[] initialKey){
        int[][] w = new int[60][4]; // word key schedule
        int i = 0;
        while (i < 8){
            int[] temp = new int[4];
            for (int j = 0; j < 4; j++){
                temp[j] = initialKey[4 * i + j];
            }
            w[i] = temp;
            i++;
        }
        while (i < 60){
            int temp[] = new int[4];
            temp = w[i - 1];
            if (i % 8 == 0){
                System.out.println("MOD 8");
                System.out.println("temp: " + Arrays.toString(temp));
                System.out.println("rotWord: " + Arrays.toString(rotWord(temp)));
                System.out.println("subBytes: " + Arrays.toString(subBytes(rotWord(temp))));
                temp = addRoundKey(subBytes(rotWord(temp)), rCon[i / 8]); // addRoundKey is just bitwise XOR of int arr arguments
                System.out.println("Bitwise XOR / addRoundKey: " + Arrays.toString(temp));
            }
            else if (i % 8 == 4){
                System.out.println("MOD 8 = 4");
                System.out.println("temp: " + Arrays.toString(temp));
                temp = subBytes(temp);
                System.out.println("subBytes: " + Arrays.toString(temp));
            }
            System.out.print("FINAL BITWISE " + i + " : ");
            w[i] = addRoundKey(w[i-8], temp);
            System.out.println(Arrays.toString(w[i]));
            i++;
        }
        // then convert word key schedule into a key schedule grouped by keys (group 4 words into one array stored in a two-dimensional key schedule)
        
        int[][] keySchedule = new int[15][16]; // 15 keys for AES-256 (14 rounds)

        for (int j = 0; j < 60; j++){
            for (int k = 0; k < 4; k++){
                keySchedule[j / 4][(j * 4 + k) % 16] = w[j][k];
            }
        }
        return keySchedule;
    }

    public static int[] generateKey() throws NoSuchAlgorithmException{
        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(256);
        SecretKey secret = gen.generateKey();
        byte[] binary = secret.getEncoded();
        int[] initialKey = new int[binary.length];
        for (int i = 0; i < binary.length; i++){
            initialKey[i] = ((int) binary[i]) + 128;
        }
        return initialKey;
    }

    public static int[] cipher(int[] input, int numRounds, int[][] keySchedule){ // numRounds = 14 for AES-256
        int[] state = input;
        addRoundKey(state, keySchedule[0]);

        for (int i = 1; i < numRounds; i++){
            state = subBytes(state);
            state = shiftRows(state);
            state = mixColumns(state);
            state = addRoundKey(state, keySchedule[i]);
            System.out.println("Round " + i + " of cipher result: " + Arrays.toString(state));
        }
        state = subBytes(state);
        state = shiftRows(state);
        state = addRoundKey(state, keySchedule[numRounds]);
        return state;
    }

    //DECRYPTION METHODS
    public static int[] invSubBytes(int[] state){
        int[] invSBox = new int[256];
        for (int i = 0; i < 256; i++){
            invSBox[sBox[i]] = i;
        }

        for (int i = 0; i < state.length; i++){
            state[i] = invSBox[state[i]];
        }
        return state;
    }

}