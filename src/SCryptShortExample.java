import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.util.encoders.Hex;

public class SCryptShortExample {
    public static void main(String[] args) throws Exception {
        byte[] hash = SCrypt.generate(
                "password".getBytes(), "salt".getBytes(), 16384, 8, 1, 16);
        System.out.println(Hex.toHexString(hash));
    }
}
