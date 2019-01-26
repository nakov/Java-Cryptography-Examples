import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import org.bouncycastle.util.encoders.Hex;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import java.security.Signature;

public class Ed25519Example {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new EdDSASecurityProvider());

        // byte[] privKeyBytes = Hex.decode("085aea0b28c9e538c871c9543602669195b46869700801c7bb2e4c2b99157563");
        // EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("Ed25519");

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EdDSA");
        var keyPair = keyGen.generateKeyPair();
        System.out.println("Private key: " +
                Hex.toHexString(keyPair.getPrivate().getEncoded()));
        System.out.println("Public key: " +
                Hex.toHexString(keyPair.getPublic().getEncoded()));

        // Sign message with EdDSA
        String msg = "Message for signing";
        Signature signer = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));
        signer.initSign(keyPair.getPrivate());
        signer.update(msg.getBytes());
        byte[] signature = signer.sign();
        System.out.println("Msg: " + msg);
        System.out.println("Signature: " + Hex.toHexString(signature));

        // Verify EdDSA signature
        Signature verifier = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));
        verifier.initVerify(keyPair.getPublic());
        verifier.update(msg.getBytes());
        boolean validSig = verifier.verify(signature);
        System.out.println("Signature valid (correct key)? " + validSig);

        // Verify EdDSA signature
        verifier = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));
        verifier.initVerify(keyGen.generateKeyPair().getPublic());
        verifier.update(msg.getBytes());
        validSig = verifier.verify(signature);
        System.out.println("Signature valid (wrong key)? " + validSig);
    }
}
