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

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
