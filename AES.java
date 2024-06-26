import java.util.Arrays;
import java.util.Base64;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.Scanner;
import java.nio.charset.StandardCharsets;

public class AES{ // AES-256, CBC, PKCS7
    private static final byte[] sBox = {
        (byte) 0x63, (byte) 0x7c, (byte) 0x77, (byte) 0x7b, (byte) 0xf2, (byte) 0x6b, (byte) 0x6f, (byte) 0xc5, (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2b, (byte) 0xfe, (byte) 0xd7, (byte) 0xab, (byte) 0x76,
        (byte) 0xca, (byte) 0x82, (byte) 0xc9, (byte) 0x7d, (byte) 0xfa, (byte) 0x59, (byte) 0x47, (byte) 0xf0, (byte) 0xad, (byte) 0xd4, (byte) 0xa2, (byte) 0xaf, (byte) 0x9c, (byte) 0xa4, (byte) 0x72, (byte) 0xc0,
        (byte) 0xb7, (byte) 0xfd, (byte) 0x93, (byte) 0x26, (byte) 0x36, (byte) 0x3f, (byte) 0xf7, (byte) 0xcc, (byte) 0x34, (byte) 0xa5, (byte) 0xe5, (byte) 0xf1, (byte) 0x71, (byte) 0xd8, (byte) 0x31, (byte) 0x15,
        (byte) 0x04, (byte) 0xc7, (byte) 0x23, (byte) 0xc3, (byte) 0x18, (byte) 0x96, (byte) 0x05, (byte) 0x9a, (byte) 0x07, (byte) 0x12, (byte) 0x80, (byte) 0xe2, (byte) 0xeb, (byte) 0x27, (byte) 0xb2, (byte) 0x75,
        (byte) 0x09, (byte) 0x83, (byte) 0x2c, (byte) 0x1a, (byte) 0x1b, (byte) 0x6e, (byte) 0x5a, (byte) 0xa0, (byte) 0x52, (byte) 0x3b, (byte) 0xd6, (byte) 0xb3, (byte) 0x29, (byte) 0xe3, (byte) 0x2f, (byte) 0x84,
        (byte) 0x53, (byte) 0xd1, (byte) 0x00, (byte) 0xed, (byte) 0x20, (byte) 0xfc, (byte) 0xb1, (byte) 0x5b, (byte) 0x6a, (byte) 0xcb, (byte) 0xbe, (byte) 0x39, (byte) 0x4a, (byte) 0x4c, (byte) 0x58, (byte) 0xcf,
        (byte) 0xd0, (byte) 0xef, (byte) 0xaa, (byte) 0xfb, (byte) 0x43, (byte) 0x4d, (byte) 0x33, (byte) 0x85, (byte) 0x45, (byte) 0xf9, (byte) 0x02, (byte) 0x7f, (byte) 0x50, (byte) 0x3c, (byte) 0x9f, (byte) 0xa8,
        (byte) 0x51, (byte) 0xa3, (byte) 0x40, (byte) 0x8f, (byte) 0x92, (byte) 0x9d, (byte) 0x38, (byte) 0xf5, (byte) 0xbc, (byte) 0xb6, (byte) 0xda, (byte) 0x21, (byte) 0x10, (byte) 0xff, (byte) 0xf3, (byte) 0xd2,
        (byte) 0xcd, (byte) 0x0c, (byte) 0x13, (byte) 0xec, (byte) 0x5f, (byte) 0x97, (byte) 0x44, (byte) 0x17, (byte) 0xc4, (byte) 0xa7, (byte) 0x7e, (byte) 0x3d, (byte) 0x64, (byte) 0x5d, (byte) 0x19, (byte) 0x73,
        (byte) 0x60, (byte) 0x81, (byte) 0x4f, (byte) 0xdc, (byte) 0x22, (byte) 0x2a, (byte) 0x90, (byte) 0x88, (byte) 0x46, (byte) 0xee, (byte) 0xb8, (byte) 0x14, (byte) 0xde, (byte) 0x5e, (byte) 0x0b, (byte) 0xdb,
        (byte) 0xe0, (byte) 0x32, (byte) 0x3a, (byte) 0x0a, (byte) 0x49, (byte) 0x06, (byte) 0x24, (byte) 0x5c, (byte) 0xc2, (byte) 0xd3, (byte) 0xac, (byte) 0x62, (byte) 0x91, (byte) 0x95, (byte) 0xe4, (byte) 0x79,
        (byte) 0xe7, (byte) 0xc8, (byte) 0x37, (byte) 0x6d, (byte) 0x8d, (byte) 0xd5, (byte) 0x4e, (byte) 0xa9, (byte) 0x6c, (byte) 0x56, (byte) 0xf4, (byte) 0xea, (byte) 0x65, (byte) 0x7a, (byte) 0xae, (byte) 0x08,
        (byte) 0xba, (byte) 0x78, (byte) 0x25, (byte) 0x2e, (byte) 0x1c, (byte) 0xa6, (byte) 0xb4, (byte) 0xc6, (byte) 0xe8, (byte) 0xdd, (byte) 0x74, (byte) 0x1f, (byte) 0x4b, (byte) 0xbd, (byte) 0x8b, (byte) 0x8a,
        (byte) 0x70, (byte) 0x3e, (byte) 0xb5, (byte) 0x66, (byte) 0x48, (byte) 0x03, (byte) 0xf6, (byte) 0x0e, (byte) 0x61, (byte) 0x35, (byte) 0x57, (byte) 0xb9, (byte) 0x86, (byte) 0xc1, (byte) 0x1d, (byte) 0x9e,
        (byte) 0xe1, (byte) 0xf8, (byte) 0x98, (byte) 0x11, (byte) 0x69, (byte) 0xd9, (byte) 0x8e, (byte) 0x94, (byte) 0x9b, (byte) 0x1e, (byte) 0x87, (byte) 0xe9, (byte) 0xce, (byte) 0x55, (byte) 0x28, (byte) 0xdf,
        (byte) 0x8c, (byte) 0xa1, (byte) 0x89, (byte) 0x0d, (byte) 0xbf, (byte) 0xe6, (byte) 0x42, (byte) 0x68, (byte) 0x41, (byte) 0x99, (byte) 0x2d, (byte) 0x0f, (byte) 0xb0, (byte) 0x54, (byte) 0xbb, (byte) 0x16,
    };

    private static final byte[][] rCon = {
        {(byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00}, 
        {(byte) 0x02, (byte) 0x00, (byte) 0x00, (byte) 0x00}, 
        {(byte) 0x04, (byte) 0x00, (byte) 0x00, (byte) 0x00}, 
        {(byte) 0x08, (byte) 0x00, (byte) 0x00, (byte) 0x00}, 
        {(byte) 0x10, (byte) 0x00, (byte) 0x00, (byte) 0x00}, 
        {(byte) 0x20, (byte) 0x00, (byte) 0x00, (byte) 0x00}, 
        {(byte) 0x40, (byte) 0x00, (byte) 0x00, (byte) 0x00}, 
        {(byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00}, 
        {(byte) 0x1b, (byte) 0x00, (byte) 0x00, (byte) 0x00}, 
        {(byte) 0x36, (byte) 0x00, (byte) 0x00, (byte) 0x00}
    };

    private static final byte[] invSBox = new byte[256]; // use sBox to init invSBox
    static{
        for (int i = 0; i < 256; i++){
            invSBox[sBox[i] & 0xFF] = (byte) i;
        }
    }

    public static void main(String[] args) throws Exception{

        /*
        byte[] key = generateKey();
        byte[] iv = generateIV();
        String plaintext = "Hello World !!!!";

        byte[] encrypted = encrypt(plaintext, key, iv);
        System.out.println("Random Key: " + Arrays.toString(key)); // alternatively, use bytesToHex to see byte arr as hex
        System.out.println("Random IV: " + Arrays.toString(iv));
        System.out.println("Random Encrypted: " + Arrays.toString(encrypted));

        String knownKey = "qwertyuiopasdfghjklzxcvbnmqwerty"; //32 char
        String knownIV = "encryptionAESvec"; //16 char
        byte[] encrypted2 = encrypt(plaintext, knownKey.getBytes(), knownIV.getBytes());
        System.out.println("Known Key: " + knownKey);
        System.out.println("Known IV: " + knownIV);
        System.out.println("Known Encrypted: " + Base64.getEncoder().encodeToString(encrypted2) + " Length: " + Base64.getEncoder().encodeToString(encrypted2).length());
        System.out.println("According to website, the answer should be: MKKN/VNcTEOqXx+PhrLNR7WrPNQsaNGa+cgjSLZuF9Q= Length: " + "MKKN/VNcTEOqXx+PhrLNR7WrPNQsaNGa+cgjSLZuF9Q=".length());

        byte[] cryptoToolKey = new byte[] {0x71, 0x77, 0x65, 0x72, 0x74, 0x79, 0x75, 0x69, 0x6F, 0x70, 0x61, 0x73, 0x64, 0x66, 0x67, 0x68, 0x6A, 0x6B, 0x6C, 0x7A, 0x78, 0x63, 0x76, 0x62, 0x6E, 0x6D, 0x71, 0x77, 0x65, 0x72, 0x74, 0x79, 0x30, (byte)0xE5, (byte)0xD3, 0x3F, 0x44, (byte)0x9C, (byte)0xA6, 0x56, 0x2B, (byte)0xEC, (byte)0xC7, 0x25, 0x4F, (byte)0x8A, (byte)0xA0, 0x4D, (byte)0xEE, 0x15, (byte)0x8C, (byte)0x99, (byte)0x96, 0x76, (byte)0xFA, (byte)0xFB, (byte)0xF8, 0x1B, (byte)0x8B, (byte)0x8C, (byte)0x9D, 0x69, (byte)0xFF, (byte)0xF5, (byte)0xCB, (byte)0xF3, 0x35, 0x61, (byte)0x8F, 0x6F, (byte)0x93, 0x37, (byte)0xA4, (byte)0x83, 0x54, 0x12, (byte)0xEB, 0x09, (byte)0xF4, 0x5F, 0x07, 0x14, 0x33, 0x56, (byte)0x91, 0x62, (byte)0xC9, (byte)0xAD, 0x69, 0x79, 0x42, 0x21, (byte)0xF4, 0x10, (byte)0xBD, (byte)0xD4, 0x05, (byte)0x89, 0x7D, (byte)0xDE, (byte)0x8A, (byte)0xE6, (byte)0xEE, (byte)0xE9, 0x2E, 0x65, (byte)0xBA, (byte)0xFB, (byte)0xC5, 0x6C, 0x4E, (byte)0xA4, (byte)0xA1, 0x44, 0x1C, 0x1F, 0x30, 0x26, (byte)0xD5, (byte)0xB2, 0x59, 0x5F, (byte)0x97, (byte)0x93, (byte)0xAD, 0x4F, 0x2A, 0x47, (byte)0x89, 0x6C, (byte)0xDD, 0x4B, 0x03, (byte)0x8A, 0x33, (byte)0xA2, 0x2D, (byte)0xEF, (byte)0x89, 0x59, (byte)0xE8, (byte)0x83, (byte)0xC7, (byte)0xFD, 0x3A, (byte)0xA8, (byte)0xDA, 0x4B, 0x0A, (byte)0x8E, 0x0F, (byte)0xF9, 0x53, (byte)0xD1, (byte)0x98, 0x6A, (byte)0xFE, (byte)0x9E, (byte)0xB2, 0x2D, (byte)0x92, 0x5B, 0x05, (byte)0xF0, (byte)0x91, (byte)0xD1, 0x36, 0x52, (byte)0xBC, 0x3E, (byte)0xBF, 0x0B, 0x54, (byte)0xBD, 0x78, (byte)0xF6, 0x1A, (byte)0xD2, 0x66, 0x09, 0x10, 0x5C, 0x69, (byte)0xF0, 0x43, (byte)0x8D, (byte)0xF1, (byte)0x9A, (byte)0xBD, 0x13, 0x43, (byte)0xB7, (byte)0xCF, 0x41, (byte)0xAC, (byte)0x8A, 0x5E, (byte)0x90, (byte)0x9A, (byte)0xD8, (byte)0xE2, (byte)0xAE, 0x25, (byte)0xD3, (byte)0xB6, 0x13, 0x5D, 0x25, 0x54, (byte)0xAF, 0x2A, 0x36, 0x44, (byte)0xF3, 0x43, (byte)0xC6, 0x07, 0x7E, (byte)0xB2, 0x5C, (byte)0xBA, 0x6D, (byte)0xF1, (byte)0xEB, (byte)0xB3, (byte)0xE0, 0x45, 0x7E, (byte)0xED, 0x70, (byte)0xDF, (byte)0xA6, 0x0F, (byte)0xDE, (byte)0xFA, 0x75, (byte)0xB9, (byte)0xCD, (byte)0xA7, 0x50};
        System.out.println("cryptoTool keySchedule" + Arrays.toString(cryptoToolKey));
        byte[] encrypted3 = cipher(pad(plaintext.getBytes()), cryptoToolKey, knownIV.getBytes());
        System.out.println("New Encrypted: " + Base64.getEncoder().encodeToString(encrypted3) + " Length: " + Base64.getEncoder().encodeToString(encrypted3).length());
        */

        Scanner scanner = new Scanner(System.in);
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        String plaintext = "";
        String ciphertext = "";

        int EnOrDe = 0;
        while (EnOrDe == 0){
            System.out.println("AES-256 CBC Mode; Would you like to encrypt or decrypt? (E/D): ");
            String EorD = scanner.nextLine().trim();
            if ("E".equalsIgnoreCase(EorD)){
                EnOrDe = 1;

                boolean gotKey = false;
                while (gotKey == false){
                    System.out.println("Enter a 32-character key or type 'generate' to create a random key: ");
                    String input = scanner.nextLine().trim(); // avoid trailing/leading spaces
                    if ("generate".equalsIgnoreCase(input)){
                        key = generateKey();
                        gotKey = true;
                    } 
                    else if (input.length() == 32){
                        key = input.getBytes();
                        gotKey = true;
                    }
                    else {
                        System.out.println("Invalid key length. Please enter exactly 32 characters or type 'generate'.");
                    }
                }
        
                boolean gotIV = false;
                while (gotIV == false){
                    System.out.println("Enter a 16-character IV or type 'generate' to create a random IV: ");
                    String input = scanner.nextLine().trim();
                    if ("generate".equalsIgnoreCase(input)){
                        iv = generateIV();
                        gotIV = true;
                    } 
                    else if (input.length() == 16){
                        iv = input.getBytes();
                        gotIV = true;
                    } 
                    else{
                        System.out.println("Invalid IV length. Please enter exactly 16 characters or type 'generate'.");
                    }
                }
        
                boolean gotText = false;
                while (gotText == false){
                    System.out.println("Enter plaintext of any length to be encrypted: ");
                    plaintext = scanner.nextLine();
                    System.out.println("Is the following plaintext correct? (Y/N): " + "'" + plaintext + "'");
                    String confirmation = scanner.nextLine().trim();
                    if ("Y".equalsIgnoreCase(confirmation)){
                        gotText = true;
                    }
                    else if ("N".equalsIgnoreCase(confirmation)){
                        plaintext = "";
                    }
                    else{
                        System.out.println("Invalid confirmation, type 'Y' or 'N'.");
                    }
                }
        
                int format = 0;
                while (format == 0){
                    System.out.println("Do you want your results in Base64 or Hex? (1 for Base64, 2 for Hex): ");
                    String choice = scanner.nextLine().trim();
                    if ("1".equals(choice)){
                        format = 1;
                    }
                    else if ("2".equals(choice)){
                        format = 2;
                    }
                    else{
                        System.out.println("Invalid choice, type '1' or '2'. ");
                    }
                }
        
                byte[] encrypted = encrypt(plaintext, key, iv);
        
                if (format == 1){
                    System.out.println("Key (Base64): " + Base64.getEncoder().encodeToString(key));
                    System.out.println("IV (Base64): " + Base64.getEncoder().encodeToString(iv));
                    System.out.println("Encrypted Ciphertext (Base64): " + Base64.getEncoder().encodeToString(encrypted));
                }
                else if (format == 2){
                    System.out.println("Key (Hex): " + bytesToHex(key));
                    System.out.println("IV (Hex): " + bytesToHex(iv));
                    System.out.println("Encrypted Ciphertext (Hex): " + bytesToHex(encrypted));
                    System.out.println("Decrypted Ciphertext (Hex): " + new String (decrypt(bytesToHex(encrypted), key, iv, format), StandardCharsets.UTF_8));
                }
            }
            else if ("D".equalsIgnoreCase(EorD)){
                EnOrDe = 2;
                boolean gotKey = false;
                while (gotKey == false){
                    System.out.println("Enter a 32-character key: ");
                    String input = scanner.nextLine().trim(); // avoid trailing/leading spaces
                    if (input.length() == 32){
                        key = input.getBytes();
                        gotKey = true;
                    }
                    else {
                        System.out.println("Invalid key length. Please enter exactly 32 characters or type 'generate'.");
                    }
                }
        
                boolean gotIV = false;
                while (gotIV == false){
                    System.out.println("Enter a 16-character IV: ");
                    String input = scanner.nextLine().trim();
                    if (input.length() == 16){
                        iv = input.getBytes();
                        gotIV = true;
                    } 
                    else{
                        System.out.println("Invalid IV length. Please enter exactly 16 characters or type 'generate'.");
                    }
                }
        
                boolean gotText = false;
                while (gotText == false){
                    System.out.println("Enter your ciphertext (Base64 and Hex accepted): ");
                    ciphertext = scanner.nextLine();
                    System.out.println("Is the following ciphertext correct? (Y/N): " + "'" + ciphertext + "'");
                    String confirmation = scanner.nextLine().trim();
                    if ("Y".equalsIgnoreCase(confirmation)){
                        gotText = true;
                    }
                    else if ("N".equalsIgnoreCase(confirmation)){
                        ciphertext = "";
                    }
                    else{
                        System.out.println("Invalid confirmation, type 'Y' or 'N'.");
                    }
                }
        
                int format = 0;
                while (format == 0){
                    System.out.println("Is your ciphertext in Base64 or Hex? (1 for Base64, 2 for Hex): ");
                    String choice = scanner.nextLine().trim();
                    if ("1".equals(choice)){
                        format = 1;
                    }
                    else if ("2".equals(choice)){
                        format = 2;
                    }
                    else{
                        System.out.println("Invalid choice, type '1' or '2'. ");
                    }
                }
        
                byte[] decrypted = decrypt(ciphertext, key, iv, format);
        
                if (format == 1){
                    System.out.println("Key (Base64): " + Base64.getEncoder().encodeToString(key));
                    System.out.println("IV (Base64): " + Base64.getEncoder().encodeToString(iv));
                    System.out.println("Decrypted Ciphertext (Plaintext): " + new String (decrypted, StandardCharsets.UTF_8));
                }
                else if (format == 2){
                    System.out.println("Key (Hex): " + bytesToHex(key));
                    System.out.println("IV (Hex): " + bytesToHex(iv));
                    System.out.println("Decrypted Ciphertext (Plaintext): " + new String (decrypted, StandardCharsets.UTF_8));
                }
            }
            else{
                System.out.println("Invalid option, type 'E' for encrypt or 'D' for decrypt.");
            }
        }

        
        scanner.close();
    }

    public static String bytesToHex(byte[] bytes){
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes){
            String hex = Integer.toHexString(0xFF & b);
            if (hex.length() == 1){
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private static byte[] pad(byte[] plaintextBytes){ // PKCS7 padding
        int paddingNeeded = 16 - (plaintextBytes.length % 16);
        byte[] padded = new byte[plaintextBytes.length + paddingNeeded];
        System.arraycopy(plaintextBytes, 0, padded, 0, plaintextBytes.length);
        for (int i = plaintextBytes.length; i < padded.length; i++){
            padded[i] = (byte) paddingNeeded;
        }
        return padded;
    }

    public static byte[] encrypt(String plaintext, byte[] key, byte[] iv) throws Exception{
        byte[] plaintextBytes = plaintext.getBytes();
        plaintextBytes = pad(plaintextBytes);
        byte[] keySchedule = keyExpansion(key);
        return cipher(plaintextBytes, keySchedule, iv);
    }

    private static byte[] cipher(byte[] input, byte[] keySchedule, byte[] iv){
        byte[] output = new byte[input.length];
        byte[] previousBlock = Arrays.copyOf(iv, iv.length); // Start with the IV

        for (int i = 0; i < input.length; i += 16){
            byte[] block = Arrays.copyOfRange(input, i, i + 16);

            for (int j = 0; j < 16; j++){
                block[j] ^= previousBlock[j];
            }

            block = encryptBlock(block, keySchedule);
            System.arraycopy(block, 0, output, i, 16);
            previousBlock = block;
        }

        return output;
    }

    private static byte[] encryptBlock(byte[] input, byte[] keySchedule){ // old cipher/NIST cipher
        byte[] state = Arrays.copyOf(input, input.length);
    
        addRoundKey(state, Arrays.copyOfRange(keySchedule, 0, 16));
    
        for (int round = 1; round < 14; round++){
            //System.out.println("Start of round " + round + ": " + bytesToHex(state));
            subBytes(state);
            //System.out.println("After subBytes: " + bytesToHex(state));
            shiftRows(state);
            //System.out.println("After shiftRows: " + bytesToHex(state));
            mixColumns(state);
            //System.out.println("After mixColumns: " + bytesToHex(state));
            addRoundKey(state, Arrays.copyOfRange(keySchedule, 16 * round, 16 * (round + 1)));
            //System.out.println("After XOR/addRoundKey: " + bytesToHex(state));
        }

        //System.out.println("Start of round final: " + bytesToHex(state));
        subBytes(state);
        //System.out.println("After subBytes: " + bytesToHex(state));
        shiftRows(state);
        //System.out.println("After shiftRows: " + bytesToHex(state));
        addRoundKey(state, Arrays.copyOfRange(keySchedule, 16 * 14, 16 * 15));
        //System.out.println("After XOR/addRoundKey: " + bytesToHex(state));
    
        return state;
    }


    private static byte[] keyExpansion(byte[] key){
        int Nb = 4;
        int Nk = key.length / 4;
        int Nr = Nk + 6;
        byte[] expandedKey = new byte[Nb * (Nr + 1) * 4];
    
        System.arraycopy(key, 0, expandedKey, 0, key.length);
        byte[] temp = new byte[4];
        int rconIter = 0;
    
        for (int i = Nk; i < Nb * (Nr + 1); i++){
            System.arraycopy(expandedKey, (i - 1) * 4, temp, 0, 4);
    
            if (i % Nk == 0){
                //System.out.println("Before rotateWord: " + Arrays.toString(temp));
                temp = rotateWord(temp);
                //System.out.println("After rotateWord: " + Arrays.toString(temp));
                temp = subWord(temp);
                //System.out.println("After subWord: " + Arrays.toString(temp));
                temp[0] ^= rCon[rconIter][0];
                //System.out.println("After rCon: " + Arrays.toString(temp) + " with rCon[" + rconIter + "][0]: " + rCon[rconIter][0]);
                rconIter++;
            }
            else if (Nk > 6 && i % Nk == 4){
                temp = subWord(temp);
                //System.out.println("After additional subWord: " + Arrays.toString(temp));
            }
    
            for (int j = 0; j < 4; j++){
                //System.out.println("XORing: " + temp[j] + " with " + expandedKey[(i - Nk) * 4 + j] + ", which is at " + (i - Nk) * 4 + j);
                expandedKey[i * 4 + j] = (byte) (expandedKey[(i - Nk) * 4 + j] ^ temp[j]);
            }
            //System.out.println("New keys added: " + Arrays.toString(Arrays.copyOfRange(expandedKey, i * 4, i * 4 + 4)));
        }
    
        //System.out.println("Final expanded key: " + Arrays.toString(expandedKey));
        return expandedKey;
    }    

    private static byte[] rotateWord(byte[] input){
        byte temp = input[0];
        System.arraycopy(input, 1, input, 0, input.length - 1);
        input[input.length - 1] = temp;
        return input;
    }

    private static byte[] subWord(byte[] input){
        for (int i = 0; i < input.length; i++){
            input[i] = (byte) sBox[input[i] & 0xFF];
        }
        return input;
    }

    private static void addRoundKey(byte[] state, byte[] roundKey){
        for (int i = 0; i < state.length; i++){
            state[i] ^= roundKey[i];
        }
    }

    private static void subBytes(byte[] state){
        for (int i = 0; i < state.length; i++){
            state[i] = (byte) sBox[state[i] & 0xFF];
        }
    }

    /*
    private static void shiftRows(byte[] state){
        byte[] shiftedState = new byte[16];
        for (int i = 0; i < 16; i++){
            int row = i / 4;
            int column = i % 4;
            shiftedState[i] = (byte) state[i + (row - 4 * ((row+column)/4))];
        }

        System.arraycopy(shiftedState, 0, state, 0, state.length);
    }
    */
    private static void shiftRows(byte[] state){
        byte[] temp = new byte[16];
    
        temp[0] = state[0];
        temp[4] = state[4];
        temp[8] = state[8];
        temp[12] = state[12];
    
        temp[1] = state[5];
        temp[5] = state[9];
        temp[9] = state[13];
        temp[13] = state[1];
    
        temp[2] = state[10];
        temp[6] = state[14];
        temp[10] = state[2];
        temp[14] = state[6];
    
        temp[3] = state[15];
        temp[7] = state[3];
        temp[11] = state[7];
        temp[15] = state[11];
    
        System.arraycopy(temp, 0, state, 0, 16);
    }    

    private static void mixColumns(byte[] state){
        byte[] mixedState = new byte[16];
        
        for (int i = 0; i < 4; i++){
            int columnBase = i * 4;
            byte s0 = state[columnBase];
            byte s1 = state[columnBase + 1];
            byte s2 = state[columnBase + 2];
            byte s3 = state[columnBase + 3];
            
            mixedState[columnBase] = (byte) (gmul(s0, (byte) 0x02) ^ gmul(s1, (byte) 0x03) ^ s2 ^ s3);
            mixedState[columnBase + 1] = (byte) (s0 ^ gmul(s1, (byte) 0x02) ^ gmul(s2, (byte) 0x03) ^ s3);
            mixedState[columnBase + 2] = (byte) (s0 ^ s1 ^ gmul(s2, (byte) 0x02) ^ gmul(s3, (byte) 0x03));
            mixedState[columnBase + 3] = (byte) (gmul(s0, (byte) 0x03) ^ s1 ^ s2 ^ gmul(s3, (byte) 0x02));
        }
        
        System.arraycopy(mixedState, 0, state, 0, state.length);
    }
    
    private static byte gmul(byte a, byte b){
        byte product = 0;
        byte hiBitSet;
        for (int i = 0; i < 8; i++){
            if ((b & 1) != 0){
                product ^= a;
            }
            hiBitSet = (byte) (a & 0x80);
            a <<= 1;
            if (hiBitSet != 0){
                a ^= 0x1b;
            }
            b >>= 1;
        }
        return product;
    }
    
    public static byte[] generateKey() throws Exception{
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // for AES-256
        SecretKey secretKey = keyGen.generateKey();
        return secretKey.getEncoded();
    }

    public static byte[] generateIV() throws Exception{ // just random
        byte[] ivBytes = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(ivBytes);
        return ivBytes;
    }

    //DECRYPTION METHODS
    private static void invSubBytes(byte[] state){
        for (int i = 0; i < state.length; i++){
            state[i] = invSBox[state[i] & 0xFF];
        }
    }
    
    private static void invShiftRows(byte[] state){
        byte[] temp = new byte[16];
    
        temp[0] = state[0];
        temp[4] = state[4];
        temp[8] = state[8];
        temp[12] = state[12];
    
        temp[1] = state[13];
        temp[5] = state[1];
        temp[9] = state[5];
        temp[13] = state[9];
    
        temp[2] = state[10];
        temp[6] = state[14];
        temp[10] = state[2];
        temp[14] = state[6];
    
        temp[3] = state[7];
        temp[7] = state[11];
        temp[11] = state[15];
        temp[15] = state[3];
    
        System.arraycopy(temp, 0, state, 0, 16);
    }
    
    private static void invMixColumns(byte[] state){
        byte[] temp = new byte[16];
    
        for (int i = 0; i < 4; i++){
            int columnBase = i * 4;
            byte s0 = state[columnBase];
            byte s1 = state[columnBase + 1];
            byte s2 = state[columnBase + 2];
            byte s3 = state[columnBase + 3];
    
            temp[columnBase] = (byte) (gmul(s0, (byte) 0x0e) ^ gmul(s1, (byte) 0x0b) ^ gmul(s2, (byte) 0x0d) ^ gmul(s3, (byte) 0x09));
            temp[columnBase + 1] = (byte) (gmul(s0, (byte) 0x09) ^ gmul(s1, (byte) 0x0e) ^ gmul(s2, (byte) 0x0b) ^ gmul(s3, (byte) 0x0d));
            temp[columnBase + 2] = (byte) (gmul(s0, (byte) 0x0d) ^ gmul(s1, (byte) 0x09) ^ gmul(s2, (byte) 0x0e) ^ gmul(s3, (byte) 0x0b));
            temp[columnBase + 3] = (byte) (gmul(s0, (byte) 0x0b) ^ gmul(s1, (byte) 0x0d) ^ gmul(s2, (byte) 0x09) ^ gmul(s3, (byte) 0x0e));
        }
    
        System.arraycopy(temp, 0, state, 0, 16);
    }
    
    private static byte[] decipher(byte[] ciphertext, byte[] key, byte[] iv){
        byte[] plaintext = new byte[ciphertext.length];
        byte[] previousBlock = Arrays.copyOf(iv, iv.length);
        byte[] keySchedule = keyExpansion(key);
    
        for (int i = 0; i < ciphertext.length; i += 16){
            byte[] block = Arrays.copyOfRange(ciphertext, i, i + 16);
            byte[] decryptedBlock = decryptBlock(block, keySchedule);
            for (int j = 0; j < 16; j++){
                decryptedBlock[j] ^= previousBlock[j];
            }
            System.arraycopy(decryptedBlock, 0, plaintext, i, 16);
            previousBlock = Arrays.copyOfRange(ciphertext, i, i + 16);
        }
        return plaintext;
    }

    private static byte[] decryptBlock(byte[] block, byte[] keySchedule){
        byte[] state = Arrays.copyOf(block, block.length);

        addRoundKey(state, Arrays.copyOfRange(keySchedule, 14 * 16, 15 * 16));

        for (int round = 13; round >= 0; round--){
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, Arrays.copyOfRange(keySchedule, round * 16, (round + 1) * 16));
            if (round > 0){
                invMixColumns(state);
            }
        }

        return state;
    }

    private static byte[] removePadding(byte[] plaintext){
        int paddingValue = plaintext[plaintext.length - 1];
        int lengthWithoutPadding = plaintext.length - paddingValue;
        byte[] unpadded = Arrays.copyOf(plaintext, lengthWithoutPadding);
        return unpadded;
    }

    public static byte[] hexToBytes(String s) {
        s = s.replaceAll("\\s", "").toUpperCase();
    
        int len = s.length();

        // Check if the string length is odd
        if (len % 2 != 0) {
            throw new IllegalArgumentException("Invalid hex string.");
        }
    
        byte[] bytes = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            // Using Integer.parseInt to handle parsing and catch any non-hex characters
            int byteValue = Integer.parseInt(s.substring(i, i + 2), 16);
            bytes[i / 2] = (byte) byteValue;
        }
        return bytes;
    }

    public static byte[] decrypt(String ciphertext, byte[] key, byte[] iv, int format) throws Exception{
        byte[] ciphertextBytes = new byte[0];
        byte[] keySchedule = new byte[0];
        byte[] plaintextBytes = new byte[0];
        if (format == 1){
            ciphertextBytes = Base64.getDecoder().decode(ciphertext);
            //System.out.println("ciphertextBytes: " + Arrays.toString(ciphertextBytes));
            keySchedule = keyExpansion(key);
            plaintextBytes = decipher(ciphertextBytes, keySchedule, iv);
        }
        else{ // format == 2
            ciphertextBytes = hexToBytes(ciphertext);
            //System.out.println("ciphertextBytes: " + Arrays.toString(ciphertextBytes));
            keySchedule = keyExpansion(key);
            plaintextBytes = decipher(ciphertextBytes, keySchedule, iv);
        }
        return removePadding(plaintextBytes);
    }    
}