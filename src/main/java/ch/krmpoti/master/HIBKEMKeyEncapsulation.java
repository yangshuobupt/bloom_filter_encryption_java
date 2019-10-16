package ch.krmpoti.master;

import java.math.BigInteger;
import java.util.List;
import java.util.logging.Logger;

public final class HIBKEMKeyEncapsulation {

    private static final Logger LOGGER = Logger.getLogger(HIBKEMKeyEncapsulation.class.getName());

    public static Triple<byte[], ECPoint, ECPoint> encapsulate(IBESystemParams systemParams, String id, byte[] key) {
        // The message is number one as a neutral element since in the default HIBE encryption scheme the pairing
        // result is multiplied with the message (the key in this case). In this use-case the hashed pairing result is
        // going to be XOR-ed instead.
        Triple<ExtensionFieldElement, ECPoint, ECPoint> hibePair = HierarchicalIBE.encrypt(systemParams, id,
                BigInteger.ONE.toByteArray());

        byte[] hashedKey = systemParams.getHashDigest(hibePair.getFirstElement().toByteArray(), key.length);
        byte[] encapsulatedKey = Utils.byteArraysXOR(hashedKey, key);

        return new Triple<>(encapsulatedKey, hibePair.getSecondElement(), hibePair.getThirdElement());
    }

    public static byte[] expose(IBESystemParams systemParams,
                                 Triple<byte[], ECPoint, ECPoint> ciphertext,
                                 Triple<ECPoint, ECPoint, List<ECPoint>> privateKey) {
        // As in this use-case the opposite of encapsulation is XOR instead of division as in the original HIBE
        // encryption scheme, the numerator and denominator passed to HIBE decryption have to be reversed.
        Triple<ExtensionFieldElement, ECPoint, ECPoint> hibeCiphertext = new Triple<>(null, ciphertext
                .getThirdElement(), ciphertext.getSecondElement());
        Triple<ECPoint, ECPoint, List<ECPoint>> hibePrivateKey = new Triple<>(privateKey.getSecondElement(),
                privateKey.getFirstElement(), privateKey.getThirdElement());
        byte[] hibeDecrypted = HierarchicalIBE.decrypt(systemParams, hibeCiphertext, hibePrivateKey);

        byte[] hashedKey = systemParams.getHashDigest(hibeDecrypted, ciphertext.getFirstElement().length);
        byte[] exposedKey = Utils.byteArraysXOR(hashedKey, ciphertext.getFirstElement());

        return exposedKey;
    }
}