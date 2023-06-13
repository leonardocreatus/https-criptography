import java.lang.reflect.Array;
import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CBC {
    static public String decrypt(String cipherText, String iv, String key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] ivBytes = hexStringToByteArray(iv);
        byte[] keyBytes = hexStringToByteArray(key);
        byte[] cipherBytes = hexStringToByteArray(cipherText);

        cipher.init(
                Cipher.DECRYPT_MODE,
                new SecretKeySpec(keyBytes, "AES"),
                new IvParameterSpec(ivBytes));

        byte[] decodedBytes = cipher.doFinal(cipherBytes);
        return new String(decodedBytes, StandardCharsets.UTF_8);
    }

    static public String encrypt(String plainText, String iv, String key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] ivBytes = hexStringToByteArray(iv);
        byte[] keyBytes = hexStringToByteArray(key);
        byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);

        cipher.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(keyBytes, "AES"),
                new IvParameterSpec(ivBytes));

        byte[] encodedBytes = cipher.doFinal(plainBytes);
        return byteArrayToHexString(encodedBytes);
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static String byteArrayToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString().toLowerCase();
    }
}
