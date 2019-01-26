import java.security.Security;
import java.security.MessageDigest;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class HashExamples {

    public static void main(String[] args) throws Exception {

        // Calculate SHA-256("hello") using the built-in JCA provider
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update("hello".getBytes());
        byte[] hash = digest.digest();
        System.out.println("SHA-256('hello') = " + Hex.toHexString(hash));

        // Calculate SHA3-512("hello") using the built-in JCA provider
        digest = MessageDigest.getInstance("SHA3-512");
        digest.update("hello".getBytes());
        hash = digest.digest();
        System.out.println("SHA3-512('hello') = " + Hex.toHexString(hash));

        // One-time registration of the "BouncyCastle" JCA provider
        Security.addProvider(new BouncyCastleProvider());

        // Calculate RIPEMD-160("hello") using the "BouncyCastle" provider
        digest = MessageDigest.getInstance("RIPEMD160");
        digest.update("hello".getBytes());
        hash = digest.digest();
        System.out.println("RIPEMD-160('hello') = " + Hex.toHexString(hash));

        // Calculate RIPEMD-160("hello") using the "BouncyCastle" provider
        digest = MessageDigest.getInstance("BLAKE2S-256");
        digest.update("hello".getBytes());
        hash = digest.digest();
        System.out.println("BLAKE2S-256('hello') = " + Hex.toHexString(hash));
    }
}
