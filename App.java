import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.xml.bind.DatatypeConverter;

public class App {
    /*
     * [Leonardo] Valor de A, em hexa:
     * 34af3b1aae3e0d3f385b050c39850e974b66b8e0d71f532f2e5d13fa4df1e4a5217232eeaca6d56553d95ad301aec33762e6e0e9659baef0a0f2e66a16824a7491d98cd74bc7a2c758eb4d46f53e18e6583a125b2e48802a39131d924c5237917e1fa22b03d00658dde247d207960fa1f9aba35608793d6c3afcb7b5bf3aca81
     * [Professor] Valor de B, em hexa:
     * 0089C0D6B536FC9D22D78CA9EEED390A629F4A6131F615D61FA265354E6EB2FF0DE8DF06CD5FDA7F60F1C929096DFECA77DF268AD56DE9F83327900FF949B43B1362A1962FC77342A906946E57C674646C90C0470B73C12C855759FF9E40482FF733B4BA82154ECA19AE66CF2E0C235D0B88C300E092899CAED5F0A8FB4A436EF3
     * [Professor] Mensagem cifrada, em hexa:
     * FEA89B0CB250478AE64238F6FCB9D28EF9C5D1F477CCF48C01613F98BDBD36B64CFCC52DA22E89B0AB81EFFF6D10E9F201784A5F752C23B0B07E3C70284A1F91E885BE67BFFDFE5195706213AC57D5C655D795B6FE688CE55B636EE09E38260209301CB131DFB8F07FDA5CC733DC69E9
     * 1. Decifrar a mensagem:
     * Show Leonardo. Agora inverte esta mensagem e me envia ela de volta cifrada
     * com a mesma senha
     * 2. Inverter a mensagem
     * 3. Gerar um novo IV
     * 4. Cifrar a mensagem invertida
     * [Leonardo] Mensagem cifrada, invertida, em hexa:
     * EA82BD6AD80CD593FCD1C2227D49808E215610465f3d0ffc57279669d43d2693925af0dfd7f310e3f6428dfb85e4d1e7d8027e13df750ab9892af687b32e79db57692f5fb916275129f13c23506b677014a940a300f1f791b928c8ea7cf9770b487ecde0536146fd4ef05779e9e1b448
     * [Professor] Nova mensagem cifrada, em hexa:
     * BA85DC0138FB5DBDFDEC4E29BD4EC8D4ACCC7E87CE22C567F814E1A4AAC4797B13E3245E2A59599C87264B507BCFB88E42D39D8A94E5ECE7C3E3AD3508166CB0B1887F41221FD3858E81F029DE36248C5928A2CA73F658FB80368FCD190A512CBE0B8BC2EFF53C7DE6791FC034D49B09DFB74158D6367C2F07981DACDC4A5A70B46A8C7A77E6BD1A1DE12BB825234034F34B379AFC92AEA11033E2C3FC818DBF
     * 1. Decifrar a mensagem:
     * Perfeito. Agora comenta bem o código colocando este exemplo completo como
     * comentário no início do código e submete o código no Moodle
     */
    public static void main(String[] args) throws Exception {
        /*
         * Mensagem recebida pelo professor
         */
        String cipherText = "FEA89B0CB250478AE64238F6FCB9D28EF9C5D1F477CCF48C01613F98BDBD36B64CFCC52DA22E89B0AB81EFFF6D10E9F201784A5F752C23B0B07E3C70284A1F91E885BE67BFFDFE5195706213AC57D5C655D795B6FE688CE55B636EE09E38260209301CB131DFB8F07FDA5CC733DC69E9";
        /*
         * IV são os primeiros 16 bytes da mensagem cifrada
         */
        String iv = cipherText.substring(0, 32);
        /*
         * Mensagem cifrada é o restante da mensagem
         */
        String encrypted = cipherText.substring(32);
        String key = getS();
        String decrypted = CBC.decrypt(encrypted, iv, key);
        System.out.println("decrypted: " + decrypted);

        /*
         * Inverte a mensagem
         */
        StringBuffer sb = new StringBuffer();
        sb.append(decrypted);
        sb.reverse();
        String reversed = sb.toString();

        /*
         * Gera um novo IV
         */
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[16]; // 128 bits are converted to 16 bytes;
        random.nextBytes(bytes);
        String newIv = DatatypeConverter.printHexBinary(bytes);

        /*
         * Cifra a mensagem invertida
         */
        String msgEncrypt = CBC.encrypt(reversed, newIv, key);
        System.out.println("encrypted: " + newIv + msgEncrypt);

    }

    /*
     * Retorna o valor de "a" (lowercase)
     */
    public static BigInteger getLowerA() {
        String str = "e2a203785a92622fd8d4193a7820a4f8cd2b43e0675d1902d72192c8fadc1287c5f51e57f5b4ba87af7c981fb80eaf50a0f7b67165da12f750ecb9e490c57d3e";
        BigInteger value = new BigInteger(str, 16);
        return value;
    }

    /*
     * Retorna o valor de "A" (uppercase)
     */
    public static BigInteger getUpperA() {
        BigInteger p = getP();
        BigInteger g = getG();
        BigInteger a = getLowerA();
        BigInteger A = g.modPow(a, p);
        return A;
    }

    /*
     * Retorna o valor de "p"
     */
    public static BigInteger getP() {
        String str = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371";
        BigInteger value = new BigInteger(str, 16);
        return value;
    }

    /*
     * Retorna o valor de "g"
     */
    public static BigInteger getG() {
        String str = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5";
        BigInteger value = new BigInteger(str, 16);
        return value;
    }

    /*
     * Retorna o valor de "b", fornecido pelo professor
     */
    public static BigInteger getB() {
        String str = "0089C0D6B536FC9D22D78CA9EEED390A629F4A6131F615D61FA265354E6EB2FF0DE8DF06CD5FDA7F60F1C929096DFECA77DF268AD56DE9F83327900FF949B43B1362A1962FC77342A906946E57C674646C90C0470B73C12C855759FF9E40482FF733B4BA82154ECA19AE66CF2E0C235D0B88C300E092899CAED5F0A8FB4A436EF3";
        BigInteger value = new BigInteger(str, 16);
        return value;
    }

    /*
     * Calcula e retorna o valor de "v"
     */
    public static BigInteger getV() {
        BigInteger p = getP();
        BigInteger b = getB();
        BigInteger a = getLowerA();
        return b.modPow(a, p);
    }

    /*
     * Calcula e retorna o valor de "S"
     */
    public static String getS() {
        String algorithm = "SHA-256";
        String v = getV().toString(16);
        if (!v.toUpperCase().startsWith("FE310"))
            v = "00" + v;
        return hashString(v, algorithm);
    }

    /*
     * Algortimo de hash
     */
    public static String hashString(String input, String algorithm) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] hashedBytes = Converter.hexStringToByteArray(input);
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

}