import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CBC {
    /*
     * Decifrar uma mensagem com AES/CBC/PKCS5Padding
     */
    static public String decrypt(String cipherText, String iv, String key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] ivBytes = Converter.hexStringToByteArray(iv);
        byte[] keyBytes = Converter.hexStringToByteArray(key);
        byte[] cipherBytes = Converter.hexStringToByteArray(cipherText);

        cipher.init(
                Cipher.DECRYPT_MODE,
                new SecretKeySpec(keyBytes, "AES"),
                new IvParameterSpec(ivBytes));

        byte[] decodedBytes = cipher.doFinal(cipherBytes);
        return new String(decodedBytes, StandardCharsets.UTF_8);
    }

    /*
     * Cifrar uma mensagem com AES/CBC/PKCS5Padding
     */
    static public String encrypt(String plainText, String iv, String key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] ivBytes = Converter.hexStringToByteArray(iv);
        byte[] keyBytes = Converter.hexStringToByteArray(key);
        byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);

        cipher.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(keyBytes, "AES"),
                new IvParameterSpec(ivBytes));

        byte[] encodedBytes = cipher.doFinal(plainBytes);
        return Converter.byteArrayToHexString(encodedBytes);
    }
}
