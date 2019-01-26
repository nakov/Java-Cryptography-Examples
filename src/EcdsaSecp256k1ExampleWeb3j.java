import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.web3j.crypto.*;
import java.math.BigInteger;

public class EcdsaSecp256k1ExampleWeb3j {

    static String compressPubKey(BigInteger pubKey) {
        String pubKeyYPrefix = pubKey.testBit(0) ? "03" : "02";
        String pubKeyHex = pubKey.toString(16);
        String pubKeyX = pubKeyHex.substring(0, 64);
        return pubKeyYPrefix + pubKeyX;
    }

    public static boolean verifySignature(
            byte[] msgHash, BigInteger r, BigInteger s, BigInteger pubKey) {
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        X9ECParameters curveParams = CustomNamedCurves.getByName("secp256k1");
        ECDomainParameters ecDomainParams = new ECDomainParameters(curveParams.getCurve(),
                curveParams.getG(), curveParams.getN(), curveParams.getH());
        ECPoint pubKeyPoint = curveParams.getCurve().decodePoint(pubKey.toByteArray());
        ECPublicKeyParameters ecPubKey =
                new ECPublicKeyParameters(pubKeyPoint, ecDomainParams);
        signer.init(false, ecPubKey);
        return signer.verifySignature(msgHash, r, s);
    }

    public static void main(String[] args) throws Exception {

        // Generate a random private key
        // BigInteger privKey = Keys.createEcKeyPair().getPrivateKey();

        // Load existing private key
        BigInteger privKey = new BigInteger("503e4d9ab9f06894a08b9cdccccee3c3be239d2e9f4fbc0c9d4c7d5247ac8260", 16);
        BigInteger pubKey = Sign.publicKeyFromPrivate(privKey);
        ECKeyPair keyPair = new ECKeyPair(privKey, pubKey);

        System.out.println("Private key (256 bits): " + privKey.toString(16));
        System.out.println("Public key (512 bits): " + pubKey.toString(16));
        System.out.println("Public key (compressed): " +
                compressPubKey(pubKey));

        // Sign message
        String msg = "Message for signing";
        byte[] msgHash = Hash.sha3(msg.getBytes());
        Sign.SignatureData signature =
                Sign.signMessage(msgHash, keyPair, false);

        System.out.println("Msg: " + msg);
        System.out.println("Msg hash: " + Hex.toHexString(msgHash));
        System.out.printf(
                "Signature: [r = %s, s = %s, v = %d]\n",
                Hex.toHexString(signature.getR()),
                Hex.toHexString(signature.getS()),
                signature.getV() - 27);

        // Verify signature
        //boolean validSig = verifySignature(msgHash,
        //        new BigInteger(signature.getR()), new BigInteger(signature.getS()),
        //        keyPair.getPublicKey());
        //System.out.println("Signature valid?" + validSig); // true

        // Recover the public key from the signed message + signature
        BigInteger pubKeyRecovered =
                Sign.signedMessageToKey(msg.getBytes(), signature);
        System.out.println("Recovered public key: " +
                pubKeyRecovered.toString(16));

        boolean validSignature = pubKey.equals(pubKeyRecovered);
        System.out.println("Signature valid? " + validSignature);
    }
}
