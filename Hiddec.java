import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class Hiddec {

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException, InvalidAlgorithmParameterException {
        Map<String, String> params = parseArgs(args);
        if(params == null || !validateParams(params)) {
            throw new IllegalArgumentException("Invalid arguments! Expected: key, input, output [Optional: ctr]");
        }
        String hexKey = params.get("key");
        String ctrIV = params.get("ctr");
        String outputFile = params.get("output");
        byte[] inputBytes = loadFile(params.get("input"));
        byte[] deciphered = ctrIV != null ? findHiddenBlob(inputBytes, hexKey, ctrIV) : findHiddenBlob(inputBytes, hexKey);
        if(deciphered == null) {
            System.out.println("Couldn't find hidden blob!");return;
        }
        ArrayList<Integer> blockBoundaries = findHashedKeyBoundaries(deciphered, hexKey);
        byte[] payload = extractPayload(deciphered, blockBoundaries.get(0), blockBoundaries.get(1), hexKey);
        boolean verifiedPayload = verifyPayload(deciphered, payload, blockBoundaries.get(1), hexKey);
        System.out.println(verifiedPayload ? new String(payload) : "Payload could not be verified");
        if(outputFile != null){
            writeToFile(payload, outputFile);
        }
    }

    static boolean validateParams(Map<String, String> params) {
        return params.get("key") != null && params.get("output") != null && params.get("input") != null;
    }

    static byte[] loadFile(String fileName) throws IOException {
        if(!(new File(fileName).isFile() && new File(fileName).canRead())){ throw new IllegalArgumentException("File needs to be readable!");}
        File inputFile =  new File(fileName);
        FileInputStream inputStream = new FileInputStream(inputFile);
        byte[] inputBytes = new byte[(int)inputFile.length()];
        inputStream.read(inputBytes);
        inputStream.close();
        return inputBytes;
    }

    static void writeToFile(byte[] output, String fileName) throws IOException {
        File outputFile = new File(fileName);
        FileOutputStream writer = new FileOutputStream(outputFile);
        writer.write(output);
        writer.close();
    }

    static byte[] decryptByteArr(byte[] input, String hexKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Key key = new SecretKeySpec(hexStringToByteArray(hexKey),"AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(input);
    }

    static byte[] decryptByteArr(byte[] input, String hexKey, byte[] hexIV) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Key key = new SecretKeySpec(hexStringToByteArray(hexKey),"AES");
        IvParameterSpec ivSpec = new IvParameterSpec(hexIV);
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        return cipher.doFinal(input);
    }

    static byte[] findHiddenBlob(byte[] input, String hexKey) throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException {
        byte[] hashedKey = getHashedKey(hexKey);
        int i = 0;
        while (i < input.length - hashedKey.length) {
            byte[] deciphered = decryptByteArr(sliceByteArr(input, i, i + 16), hexKey);
            if(byteArrEq(hashedKey, deciphered)){
                return decryptByteArr(sliceByteArr(input, i, input.length), hexKey);
            }
            i += 16;
        }
        return null;
    }

    static byte[] findHiddenBlob(byte[] input, String hexKey, String hexIV) throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, IOException {
        byte[] hashedKey = getHashedKey(hexKey);
        byte[] iv = hexStringToByteArray(hexIV);
        int i = 0;
        while (i < input.length - hashedKey.length) {
            byte[] deciphered = decryptByteArr(sliceByteArr(input, i, i + 16), hexKey, iv);
            if(byteArrEq(hashedKey, deciphered)){
                return extractBlobFromIndex(input, i, hexKey, hexIV);
            }
            i += 16;
        }
        return null;
    }

    static byte[] extractBlobFromIndex(byte[] input, int blobStart, String hexKey, String hexIV) throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, IOException {
        byte[] hashedKey = getHashedKey(hexKey);
        byte[] iv = hexStringToByteArray(hexIV);
        byte[] blob = decryptByteArr(sliceByteArr(input, blobStart, blobStart + 16), hexKey, iv);
        int i = blobStart + 16;
        while (i < input.length - hashedKey.length) {
            byte[] deciphered = decryptByteArr(sliceByteArr(input, i, i + 16), hexKey, addToByteArray(iv, (i - blobStart) / 16));
            if(byteArrEq(hashedKey, deciphered)){
                blob = concatByteArr(blob, deciphered);
                for(int j = 1; j <= 8; j++){
                    blob = concatByteArr(blob, decryptByteArr(sliceByteArr(input, i + j*16, i + j*16 + 16), hexKey, addToByteArray(iv, ((i - blobStart) / 16) + j)));
                }
                break;
            } else {
                blob = concatByteArr(blob, deciphered);
            }
            i += 16;
        }
        return blob;
    }

    static ArrayList<Integer> findHashedKeyBoundaries(byte[] deciphered, String hexKey) throws NoSuchAlgorithmException, IllegalBlockSizeException {
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

    static byte[] addToByteArray(byte[] arr, int toAdd) throws IOException {
        int bytes = new BigInteger(arr).intValue();
        int n = bytes + toAdd;
        byte[] a = sliceByteArr(arr, 0, arr.length - 4);
        byte[] b = BigInteger.valueOf(n).toByteArray();
        return concatByteArr(a, b);
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

    private static byte[] concatByteArr(byte[] a, byte[] b) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        outputStream.write(a);
        outputStream.write(b);
        return outputStream.toByteArray();
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
