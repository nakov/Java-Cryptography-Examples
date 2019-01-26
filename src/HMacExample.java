import org.bouncycastle.util.encoders.Hex;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

public class HMacExample {
    public static void main(String[] args) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        Key key = new SecretKeySpec("key".getBytes(), "HmacSHA256");
        mac.init(key);
        byte[] hash = mac.doFinal("hello".getBytes());
        System.out.println("HMAC-SHA-256('key', 'hello') = " +
                Hex.toHexString(hash));
    }
}
