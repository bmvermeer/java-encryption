
import java.security.GeneralSecurityException;

public class Main {

    public static void main(String[] args) throws GeneralSecurityException {



        var key = "MyDesKey";
        var desEncryption = new EncryptionServiceDes(key);

        var text = "This is the orginal text I need to encrypt";
        var cypher = desEncryption.encrypt(text);

        System.out.println(cypher);
        System.out.println(desEncryption.decrypt(cypher));

        String aesKey = "MySecretAESKey12";
        var aesEncryption = new EncryptionServiceAES(aesKey);
        cypher = aesEncryption.encrypt(text);
        System.out.println(cypher);
        System.out.println(aesEncryption.decrypt(cypher));

        var aesGcmEncryption = new EncryptionServiceAESGCM(aesKey);
        cypher = aesGcmEncryption.encrypt(text);
        System.out.println(cypher);
        System.out.println(aesGcmEncryption.decrypt(cypher));

    }
}
