import org.bouncycastle.jcajce.spec.ScryptKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKeyFactory;
import java.security.Security;

public class SCryptExample {
    public static void main(String[] args) throws Exception {
        // One-time registration of the "BouncyCastle" JCA provider
        Security.addProvider(new BouncyCastleProvider());

        ScryptKeySpec spec = new ScryptKeySpec(
                "password".toCharArray(), "salt".getBytes(),
                16384*8, 32, 1, 128);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("Scrypt");
        byte[] derivedKey = keyFactory.generateSecret(spec).getEncoded();

        System.out.println("Scrypt derived key: " + Hex.toHexString(derivedKey));
    }
}
