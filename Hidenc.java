import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public class Hidenc {
    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException, InvalidAlgorithmParameterException {
        Map<String, String> params = parseArgs(args);
        if(params == null) {
            throw new IllegalArgumentException("Invalid arguments!");
        }
        String hexKey = params.get("key");
        Integer offset = Integer.parseInt(params.get("offset"));
        String ctrIV = params.get("ctr");
        String templateFile = params.get("template");
        byte[] payload = loadFile(params.get("input"));
        byte[] block = createBlock(payload, hexKey);
        byte[] encryptedBytes = ctrIV != null ? encryptByteArr(block, hexKey, ctrIV) : encryptByteArr(block, hexKey);
        byte[] container = templateFile != null ? loadFile(templateFile) : getContainer(Integer.parseInt(params.get("size")));
        insertBlockIntoContainer(container, encryptedBytes, offset);
        writeToFile(container, params.get("output"));
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

    static byte[] createBlock(byte[] payload, String hexKey) throws NoSuchAlgorithmException {
        byte[] hashedKey = getHashedKey(hexKey);
        byte[] hashedPayload = hashPayload(payload);
        byte[] block = new byte[2*hashedKey.length + payload.length + hashedPayload.length];
        insertByteArr(hashedKey, block, 0);
        insertByteArr(payload, block, hashedKey.length);
        insertByteArr(hashedKey, block, hashedKey.length + payload.length);
        insertByteArr(hashedPayload, block, 2*hashedKey.length + payload.length);
        return block;
    }

    static byte[] getContainer(int size) {
        byte[] b = new byte[size];
        new Random().nextBytes(b);
        return b;
    }

    static void insertBlockIntoContainer(byte[] container, byte[] block, int offset) {
        for (int i = 0; i < block.length; i++) {
            container[i + offset] = block[i];
        }
    }

    static byte[] encryptByteArr(byte[] input, String hexKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Key key = new SecretKeySpec(hexStringToByteArray(hexKey),"AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(input);
    }

    static byte[] encryptByteArr(byte[] input, String hexKey, String hexIV) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        Key key = new SecretKeySpec(hexStringToByteArray(hexKey),"AES");
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        byte[] encrypted = new byte[0];
        int i = 0;
        while(i < input.length) {
            byte[] blockToEncrypt = sliceByteArr(input, i, i + 16);
            IvParameterSpec ivSpec = new IvParameterSpec(addToByteArray(hexStringToByteArray(hexIV), i / 16));
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            encrypted = concatByteArr(encrypted, cipher.doFinal(blockToEncrypt));
            i += 16;
        }
        return encrypted;
    }

    static void writeToFile(byte[] output, String fileName) throws IOException {
        File outputFile = new File(fileName);
        FileOutputStream writer = new FileOutputStream(outputFile);
        writer.write(output);
        writer.close();
    }

    static byte[] getHashedKey(String hexKey) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(hexStringToByteArray(hexKey));
    }

    static byte[] hashPayload(byte[] payload) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(payload);
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

    private static void insertByteArr(byte[] src, byte[] dest, int start) {
        for(int i = 0; i < src.length; i++) {
            dest[i + start] = src[i];
        }
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
