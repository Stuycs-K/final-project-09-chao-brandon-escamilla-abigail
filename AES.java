import java.util.Arrays;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;

public class AES{
    private static final int[] sBox = {
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

    private static final int[][] rCon = {
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

    public static void main(String[] args) throws Exception{
        byte[] key = generateKey();
        byte[] iv = generateIV();
        String plaintext = "Hello World !!!!";

        byte[] encrypted = encrypt(plaintext, key, iv);
        System.out.println("Encrypted: " + bytesToHex(encrypted));
    }

    private static String bytesToHex(byte[] bytes){
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

    private static byte[] pad(byte[] plaintextBytes){ // PKCS#7 padding
        int paddingNeeded = 16 - (plaintextBytes.length % 16);
        byte[] padded = new byte[plaintextBytes.length + paddingNeeded];
        System.arraycopy(plaintextBytes, 0, padded, 0, plaintextBytes.length);
        for (int i = plaintextBytes.length; i < padded.length; i++){
            padded[i] = (byte) paddingNeeded;
        }
        return padded;
    }

    public static byte[] encrypt(String plaintext, byte[] key, byte[] iv) throws Exception{
        // returns cipher after padding
    }

    public static byte[] cipher(byte[] input, byte[] keySchedule, byte[] iv){
        //for IV
    }

    public static byte[] encryptBlock(byte[] input, byte[] keySchedule, byte[] iv){ // old cipher/NIST cipher
        byte[] state = Arrays.copyOf(input, input.length);

        for (int round = 1; round < 14; round++){
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, Arrays.copyOfRange(keySchedule, 16 * round, 16 * (round + 1)));
        }

        subBytes(state);
        shiftRows(state);
        addRoundKey(state, Arrays.copyOfRange(keySchedule, 16 * 14, 16 * 15));

        return state;
    }


    public static byte[] keyExpansion(byte[] key){
        int Nb = 4; // block size in words
        int Nk = key.length / 4; // key size in words
        int Nr = Nk + 6; // number of rounds
        byte[] expandedKey = new byte[Nb * (Nr + 1) * 4];

        int currentSize = 0;
        int rconIter = 1;
        byte[] temp = new byte[4];

        System.arraycopy(key, 0, expandedKey, 0, key.length);
        currentSize += key.length;

        while (currentSize < expandedKey.length){
            System.arraycopy(expandedKey, currentSize - 4, temp, 0, 4);

            if (currentSize % key.length == 0){
                temp = rotateWord(temp);
                temp = subWord(temp);
                temp[0] ^= rCon[rconIter++][0];
            }

            for (int i = 0; i < temp.length; i++){
                expandedKey[currentSize] = (byte) (expandedKey[currentSize - key.length] ^ temp[i]);
                currentSize++;
            }
        }

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

    public static void addRoundKey(byte[] state, byte[] roundKey){
        for (int i = 0; i < state.length; i++){
            state[i] ^= roundKey[i];
        }
    }

    public static void subBytes(byte[] state){
        for (int i = 0; i < state.length; i++){
            state[i] = (byte) sBox[state[i] & 0xFF];
        }
    }

    public static void shiftRows(byte[] state){
        byte[] shiftedState = new byte[16];

        for (int i = 0; i < 16; i++){
            int row = i / 4;
            int column = i % 4;
            shiftedState[i] = (byte) state[i + (row - 4 * ((row+column)/4))];
        }

        System.arraycopy(shiftedState, 0, state, 0, state.length);
    }

    public static void mixColumns(byte[] state){
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
}