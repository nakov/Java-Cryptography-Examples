import de.mkammerer.argon2.Argon2Advanced;
import de.mkammerer.argon2.Argon2Factory;
import org.bouncycastle.util.encoders.Hex;

public class Argon2Example {
    public static void main(String[] args) throws Exception {
        // Import the "argon2-jvm" library from the Maven Central
        // https://mvnrepository.com/artifact/de.mkammerer/argon2-jvm/2.5

        Argon2Advanced argon2 = Argon2Factory.createAdvanced(
                Argon2Factory.Argon2Types.ARGON2id);
        byte[] rawHash = argon2.rawHash(16, 1 << 15,
                2, "password", "some salt".getBytes());
        System.out.println("Argon2 raw hash: " + Hex.toHexString(rawHash));

        String hash = argon2.hash(8, 1 << 16,
                4, "password");
        System.out.println("Argon2 hash (random salt): " + hash);
        // Keep the hash in the database to verify passwords later

        System.out.println("Argon2 verify (correct password): " +
                argon2.verify(hash, "password"));

        System.out.println("Argon2 verify (wrong password): " +
                argon2.verify(hash, "wrong123"));    }
}
