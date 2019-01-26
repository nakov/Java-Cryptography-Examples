import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class Pbkdf2Example {
    public static void main(String[] args) throws Exception {
        PBEKeySpec spec = new PBEKeySpec("password".toCharArray(),
                "salt".getBytes(), 1000000, 128);
        SecretKeyFactory keyFactory =
                SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] derivedKey = keyFactory.generateSecret(spec).getEncoded();
        System.out.println("PBKDF2 derived key: " + Hex.toHexString(derivedKey));
    }
}
