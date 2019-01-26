import de.mkammerer.argon2.Argon2Factory;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Map;

public class AesCtrArgon2HmacExample {

    private static Map<String, String> aes256CtrArgon2HMacEncrypt(
            String plainText, String password) throws Exception {

        // Derive a secret key from the encryption password
        SecureRandom rand = new SecureRandom();
        byte[] argon2salt = new byte[16];
        rand.nextBytes(argon2salt); // Generate 128-bit salt
        byte[] argon2hash = Argon2Factory.createAdvanced(
                Argon2Factory.Argon2Types.ARGON2id).rawHash(16,
                1 << 15, 2, password, argon2salt);
        Key secretKey = new SecretKeySpec(argon2hash, "AES");

        // AES encryption: {plaintext + IV + secretKey} -> ciphertext
        byte[] aesIV = new byte[16];
        rand.nextBytes(aesIV); // Generate 128-bit IV (salt)
        IvParameterSpec ivSpec = new IvParameterSpec(aesIV);
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] plainTextBytes = plainText.getBytes("utf8");
        byte[] cipherBytes = cipher.doFinal(plainTextBytes);

        // Calculate the MAC of the plaintext with the derived argon2hash
        Mac mac = Mac.getInstance("HmacSHA256");
        Key macKey = new SecretKeySpec(argon2hash, "HmacSHA256");
        mac.init(macKey);
        byte[] hmac = mac.doFinal(plainText.getBytes("utf8"));

        var encryptedMsg = Map.of(
            "kdf", "argon2",
            "kdfSalt", Hex.toHexString(argon2salt),
            "cipher", "aes-256-ctr",
            "cipherIV", Hex.toHexString(aesIV),
            "cipherText", Hex.toHexString(cipherBytes),
            "mac", Hex.toHexString(hmac)
        );
        return encryptedMsg;
    }

    static String aes256CtrArgon2HMacDecrypt(
            Map<String, String> encryptedMsg, String password) throws Exception {

        // Derive the secret key from the encryption password with argon2salt
        byte[] argon2salt = Hex.decode(encryptedMsg.get("kdfSalt"));
        byte[] argon2hash = Argon2Factory.createAdvanced(
                Argon2Factory.Argon2Types.ARGON2id).rawHash(16,
                1 << 15, 2, password, argon2salt);

        // AES decryption: {cipherText + IV + secretKey} -> plainText
        byte[] aesIV = Hex.decode(encryptedMsg.get("cipherIV"));
        IvParameterSpec ivSpec = new IvParameterSpec(aesIV);
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        Key secretKey = new SecretKeySpec(argon2hash, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] cipherTextBytes = Hex.decode(encryptedMsg.get("cipherText"));
        byte[] plainTextBytes = cipher.doFinal(cipherTextBytes);
        String plainText = new String(plainTextBytes, "utf8");

        // Calculate and check the MAC code: HMAC(plaintext, argon2hash)
        Mac mac = Mac.getInstance("HmacSHA256");
        Key macKey = new SecretKeySpec(argon2hash, "HmacSHA256");
        mac.init(macKey);
        byte[] hmac = mac.doFinal(plainText.getBytes("utf8"));
        String decodedMac = Hex.toHexString(hmac);
        String cipherTextMac = encryptedMsg.get("mac");
        if (! decodedMac.equals(cipherTextMac)) {
            throw new InvalidKeyException("MAC does not match: maybe wrong password");
        }

        return plainText;
    }

    public static void main(String[] args) throws Exception {
        var encryptedMsg =
            aes256CtrArgon2HMacEncrypt("some text", "pass@123");
        System.out.println("Encrypted msg: " + encryptedMsg);

        String decryptedPlainText = aes256CtrArgon2HMacDecrypt(
                encryptedMsg, "pass@123");
        System.out.println("Successfully decrypted: " + decryptedPlainText);

        try {
            aes256CtrArgon2HMacDecrypt(encryptedMsg, "incorrect password");
        }
        catch (Exception ex) {
            System.err.println(ex.getMessage());
        }
    }
}
