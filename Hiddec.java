import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

public class Hiddec {

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        Key key = new SecretKeySpec(hexStringToByteArray("18007fc49bc4e7a43f120cc6e33aab9f"),"AES");

        // Get cipher instance
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");

        if(false) {
            cipher.init(Cipher.ENCRYPT_MODE,key);
        }
        else {
            cipher.init(Cipher.DECRYPT_MODE,key);
        }

        // Read input file into byte array
        File inputFile =  new File("task1.data");
        FileInputStream fileInputStream = new FileInputStream(inputFile);
        byte[] inputBytes = new byte[(int)inputFile.length()];
        fileInputStream.read(inputBytes);

        String s1 = new String(inputBytes, StandardCharsets.US_ASCII);

        // Process the byte array from the input file
        byte[] outputBytes = cipher.doFinal(inputBytes);

        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hashedKey = md.digest(hexStringToByteArray("18007fc49bc4e7a43f120cc6e33aab9f"));
        ArrayList<Integer> hashIndexes = new ArrayList<>();
        int i = 0;
        while (i < outputBytes.length - hashedKey.length) {
            byte[] temp = sliceByteArr(outputBytes, i, i + hashedKey.length);
            if(byteArrEq(hashedKey, temp)){
                hashIndexes.add(i);
            }
            i++;
        }
        System.out.println("Key found at indexes: " + hashIndexes);
        String s = new String(outputBytes, StandardCharsets.US_ASCII);
        String hiddenMessage = s.substring(hashIndexes.get(0) + hashedKey.length, hashIndexes.get(1));
        System.out.println(hiddenMessage);
        byte[] hashedMsg = md.digest(hiddenMessage.getBytes());
        System.out.println(byteArrEq(hashedMsg, sliceByteArr(outputBytes, hashIndexes.get(1) + hashedKey.length, hashIndexes.get(1) + hashedKey.length + hashedMsg.length)));
        // Close file streams
        fileInputStream.close();
    }

    //Taken from https://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
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

}
