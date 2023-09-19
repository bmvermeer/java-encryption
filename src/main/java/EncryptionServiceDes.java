import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;

public class EncryptionServiceDes {

    private SecretKey secretKey;
    private Cipher cipher;

    public EncryptionServiceDes(String key) throws GeneralSecurityException {
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        DESKeySpec desKeySpec = new DESKeySpec(keyBytes);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        secretKey = keyFactory.generateSecret(desKeySpec);
        cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
    }

    public String encrypt(String original) throws GeneralSecurityException {
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        // Encrypt the original data
        byte[] encryptedData = cipher.doFinal(original.getBytes(StandardCharsets.UTF_8));
        // Encode the encrypted data in base64 for better handling
        return Base64.getEncoder().encodeToString(encryptedData);
    }
    public String decrypt(String cypher) throws GeneralSecurityException{
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        // Decode the base64-encoded ciphertext
        byte[] encryptedData = Base64.getDecoder().decode(cypher);
        // Decrypt the data
        byte[] decryptedData = cipher.doFinal(encryptedData);
        return new String(decryptedData, StandardCharsets.UTF_8);
    }
}
