import net.consensys.cava.crypto.SECP256K1;
import net.consensys.cava.crypto.Hash;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.Security;

public class EcdsaSecp256k1ExampleCava {

    static String compressPubKey(SECP256K1.PublicKey publicKey) {
        BigInteger pubKey = new BigInteger(1, publicKey.bytesArray());
        String pubKeyYPrefix = pubKey.testBit(0) ? "03" : "02";
        String pubKeyHex = pubKey.toString(16);
        String pubKeyX = pubKeyHex.substring(0, 64);
        return pubKeyYPrefix + pubKeyX;
    }

    public static void main(String[] args) throws Exception {
        // One-time registration of the "BouncyCastle" JCA provider
        Security.addProvider(new BouncyCastleProvider());

        // Generate random key-pair
        // SECP256K1.KeyPair keyPair = SECP256K1.KeyPair.random();

        // Load key-pair from existing private key
        SECP256K1.KeyPair keyPair = SECP256K1.KeyPair.fromSecretKey(SECP256K1.SecretKey.fromInteger(new BigInteger(
                "207724f0eba0800350f579726c2a8bbd1ac6385f4168e493cfd91efe522959cf", 16)));

        System.out.println("Private key (256 bits): " +
                Hex.toHexString(keyPair.secretKey().bytesArray()));
        System.out.println("Public key (512 bits): 04" +
                Hex.toHexString(keyPair.publicKey().bytesArray()));
        System.out.println("Public key (compressed): " +
                compressPubKey(keyPair.publicKey()));

        // Sign a message
        String msg = "Message for signing";
        byte[] msgHash = Hash.sha2_256(msg.getBytes());
        SECP256K1.Signature signature = SECP256K1.signHashed(msgHash, keyPair);
        System.out.println("Msg: " + msg);
        System.out.println("Msg hash: " + Hex.toHexString(msgHash));
        System.out.printf(
                "Signature: [r = %s, s = %s, v = %d]\n",
                signature.r().toString(16),
                signature.s().toString(16),
                signature.v());

        // Verify the signature
        boolean validSig = SECP256K1.verifyHashed(
                msgHash, signature, keyPair.publicKey());
        System.out.println("Signature valid (correct key)? " + validSig);

        boolean validSigWrongKey = SECP256K1.verifyHashed(
                msgHash, signature, SECP256K1.KeyPair.random().publicKey());
        System.out.println("Signature valid (wrong key)? " + validSigWrongKey);

        // Recover the public key from msg + signature
        SECP256K1.PublicKey recoveredPubKey = SECP256K1.PublicKey.
                recoverFromHashAndSignature(msgHash, signature);
        System.out.println("Recovered pubKey: 04" +
                Hex.toHexString(recoveredPubKey.bytesArray()));
        System.out.println("Signature valid ? " +
                recoveredPubKey.equals(keyPair.publicKey()));
    }
}
