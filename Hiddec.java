import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class Hiddec {

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        Map<String, String> params = parseArgs(args);
        if(params == null) {
            throw new IllegalArgumentException("Invalid arguments!");
        }
        String hexKey = params.get("key");
        byte[] inputBytes = loadFile(params.get("input"));
        byte[] decipheredBytes = decryptByteArr(inputBytes, hexKey);
        ArrayList<Integer> blockBoundaries = findHashedKeyBoundaries(decipheredBytes, hexKey);
        byte[] payload = extractPayload(decipheredBytes, blockBoundaries.get(0), blockBoundaries.get(1), hexKey);
        boolean verifiedPayload = verifyPayload(decipheredBytes, payload, blockBoundaries.get(1), hexKey);
        System.out.println(verifiedPayload ? "Payload verified to be \"" + new String(payload) + "\"" : "Payload could not be verified");
    }



    static byte[] loadFile(String fileName) throws IOException {
        if(!(new File(fileName).isFile() && new File(fileName).canRead())){ throw new IllegalArgumentException("Dictionary needs to be readable!");}
        File inputFile =  new File(fileName);
        FileInputStream inputStream = new FileInputStream(inputFile);
        byte[] inputBytes = new byte[(int)inputFile.length()];
        inputStream.read(inputBytes);
        inputStream.close();
        return inputBytes;
    }

    static byte[] decryptByteArr(byte[] input, String hexKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Key key = new SecretKeySpec(hexStringToByteArray(hexKey),"AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(input);
    }

    static byte[] decryptByteArr(byte[] input, String hexKey, String hexIV) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Key key = new SecretKeySpec(hexStringToByteArray(hexKey),"AES");
        IvParameterSpec ivSpec = new IvParameterSpec(hexStringToByteArray(hexIV));
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        return cipher.doFinal(input);
    }

    static ArrayList<Integer> findHashedKeyBoundaries(byte[] deciphered, String hexKey) throws NoSuchAlgorithmException {
        byte[] hashedKey = getHashedKey(hexKey);
        ArrayList<Integer> hashIndexes = new ArrayList<>();
        int i = 0;
        while (i < deciphered.length - hashedKey.length) {
            byte[] temp = sliceByteArr(deciphered, i, i + hashedKey.length);
            if(byteArrEq(hashedKey, temp)){
                hashIndexes.add(i);
            }
            i++;
        }
        return hashIndexes;
    }

    static byte[] extractPayload(byte[] deciphered, int blockStartKeyIndex, int blockEndKeyIndex, String hexKey) throws NoSuchAlgorithmException {
        byte[] hashedKey = getHashedKey(hexKey);
        return sliceByteArr(deciphered, blockStartKeyIndex + hashedKey.length, blockEndKeyIndex);
    }

    static boolean verifyPayload(byte[] deciphered, byte[] expected, int blockEnd, String hexKey) throws NoSuchAlgorithmException {
        byte[] hashedKey = getHashedKey(hexKey);
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hashedMsg = md.digest(expected);
        return byteArrEq(hashedMsg, sliceByteArr(deciphered, blockEnd + hashedKey.length, blockEnd + hashedKey.length + hashedMsg.length));
    }

    static byte[] getHashedKey(String hexKey) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(hexStringToByteArray(hexKey));
    }

    //Taken from https://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    private static byte[] sliceByteArr(byte[] a, int start, int end){
        byte[] temp = new byte[end - start];
        for(int i = start; i < end; i++) {
            temp[i - start] = a[i];
        }
        return temp;
    }

    private static boolean byteArrEq(byte[] a, byte[] b) {
        if(a.length != b.length)
            return false;
        boolean equal = true;
        for(int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                equal = false;
                break;
            }
        }
        return equal;
    }

    // Inspired by https://stackoverflow.com/questions/7341683/parsing-arguments-to-a-java-command-line-program
    static Map<String, String> parseArgs(String[] args){
        Map<String, String> params = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            final String a = args[i];
            if (a.charAt(0) == '-') {
                if (a.length() < 4) {
                    System.err.println("Error at argument " + a);
                    return null;
                }
                String[] argument = a.split("=");
                params.put(argument[0].substring(2), argument[1]);
            }
        }
        return params;
    }
}
