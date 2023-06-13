import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.xml.bind.DatatypeConverter;

public class App {
    public static void main(String[] args) throws Exception {
        // BigInteger A = getUpperA();
        // BigInteger p = getP();
        // BigInteger g = getG();
        // BigInteger b = getB();
        BigInteger a = getUpperA();
        // BigInteger v = getV();

        // String cipherText =
        // "FC4E3A5DBD06B75FAF00E5D11A8DF25A22098EC4DFDD7BAE15D46B85FF6686B27580729E58CDD0F9D33D946FB7A931AFE6F744CA50D1CDA065A192642872C9F5F54D18DD055B55CA36AD52D1C3CBFD7C7FC7B13E156D356950575A666872A316F7968EFA5A045DDBB808F243942D7296";
        // String cipherText =
        // "FEA89B0CB250478AE64238F6FCB9D28EF9C5D1F477CCF48C01613F98BDBD36B64CFCC52DA22E89B0AB81EFFF6D10E9F201784A5F752C23B0B07E3C70284A1F91E885BE67BFFDFE5195706213AC57D5C655D795B6FE688CE55B636EE09E38260209301CB131DFB8F07FDA5CC733DC69E9";
        String cipherText = "BA85DC0138FB5DBDFDEC4E29BD4EC8D4ACCC7E87CE22C567F814E1A4AAC4797B13E3245E2A59599C87264B507BCFB88E42D39D8A94E5ECE7C3E3AD3508166CB0B1887F41221FD3858E81F029DE36248C5928A2CA73F658FB80368FCD190A512CBE0B8BC2EFF53C7DE6791FC034D49B09DFB74158D6367C2F07981DACDC4A5A70B46A8C7A77E6BD1A1DE12BB825234034F34B379AFC92AEA11033E2C3FC818DBF";
        String iv = cipherText.substring(0, 32);
        String encrypted = cipherText.substring(32);

        String key = getS();

        String decrypted = CBC.decrypt(encrypted, iv, key);
        System.out.println("decrypted: " + decrypted);
        // StringBuffer sb = new StringBuffer();
        // sb.append(decrypted);
        // sb.reverse();
        // String reversed = sb.toString();

        // SecureRandom random = new SecureRandom();
        // byte bytes[] = new byte[16]; // 128 bits are converted to 16 bytes;
        // random.nextBytes(bytes);
        // String iv2 = DatatypeConverter.printHexBinary(bytes);

        // String encrypted2 = CBC.encrypt(reversed, iv2, key);
        // System.out.println("encrypted: " + iv2 + encrypted2);

    }

    public static BigInteger getLowerA() {
        String str = "e2a203785a92622fd8d4193a7820a4f8cd2b43e0675d1902d72192c8fadc1287c5f51e57f5b4ba87af7c981fb80eaf50a0f7b67165da12f750ecb9e490c57d3e";

        // String str =
        // "78229202513324640203383948911050967690556374666583189445530352392682597377261887909618512668247103766248595753399990588713756675798860877218282300744954892075710466620972447248389727958996402752546971";
        BigInteger value = new BigInteger(str, 16);
        return value;
    }

    public static BigInteger getUpperA() {
        BigInteger p = getP();
        BigInteger g = getG();
        BigInteger a = getLowerA();
        BigInteger A = g.modPow(a, p);
        return A;
    }

    public static BigInteger getP() {
        // String str =
        // "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371";
        String str = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371";
        BigInteger value = new BigInteger(str, 16);
        return value;
    }

    public static BigInteger getG() {
        // String str =
        // "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5";
        String str = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5";
        BigInteger value = new BigInteger(str, 16);
        return value;
    }

    public static BigInteger getB() {
        String str = "0089C0D6B536FC9D22D78CA9EEED390A629F4A6131F615D61FA265354E6EB2FF0DE8DF06CD5FDA7F60F1C929096DFECA77DF268AD56DE9F83327900FF949B43B1362A1962FC77342A906946E57C674646C90C0470B73C12C855759FF9E40482FF733B4BA82154ECA19AE66CF2E0C235D0B88C300E092899CAED5F0A8FB4A436EF3";
        // String str =
        // "1A20733EA06190EFA639F092FC22A9EB5BCA9CCA1A41AE4B3263D2C8F0907D709014D630F95FBF69B074A6FE7DC1E1A0B11B93CE7E8B9A41C6C67DD74EAA9A4833879251F3DD25246D104B1CC8928C2527F1A15147394CF21D572FBEB05F0D44E782F5AEC4ADF8DE68D252B8A2A848DC5DFBE7B2BDB8AE56AD123C9F12BC3900";
        BigInteger value = new BigInteger(str, 16);
        return value;
    }

    public static BigInteger getV() {
        BigInteger p = getP();
        BigInteger b = getB();
        BigInteger a = getLowerA();
        return b.modPow(a, p);
    }

    public static String hashString(String input, String algorithm) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] hashedBytes = hexStringToByteArray(input);
            hashedBytes = digest.digest(hashedBytes);
            StringBuffer hash = new StringBuffer();
            for (byte b : hashedBytes) {
                hash.append(String.format("%02x", b & 0xFF));
            }
            return hash.toString().substring(0, 32);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null; // Return null if an error occurs
    }

    public static String getS() {
        String algorithm = "SHA-256";
        String v = getV().toString(16);
        if (!v.toUpperCase().startsWith("FE310"))
            v = "00" + v;
        return hashString(v, algorithm);
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