package ch.krmpoti.master;

import iaik.security.ec.math.curve.AtePairingOverBarretoNaehrigCurveFactory;
import iaik.security.ec.math.curve.PairingTypes;

import java.math.BigInteger;
import java.util.logging.Logger;

public final class BonehFranklinIBE {

    private static final Logger LOGGER = Logger.getLogger(BonehFranklinIBE.class.getName());

    public static Pair<IBESystemParams, BigInteger> setup(int k) {
        if (k < 1) {
            throw new IllegalArgumentException("Provided k value has to be positive!");
        }

        IBESystemParams systemParams = new IBESystemParamsImpl(
                new PairingImpl(AtePairingOverBarretoNaehrigCurveFactory.getPairing(PairingTypes.TYPE_3, k)));

        BigInteger masterKey = Utils.generateRandomPositiveBigInteger(systemParams.getOrder());
        systemParams.setPublicKey(systemParams.getGroup1Generator().multiplyPoint(masterKey));

        return new Pair<>(systemParams, masterKey);
    }

    public static ECPoint extract(IBESystemParams systemParams, BigInteger masterKey, byte[] id) {
        ECPoint Qid = systemParams.getGroup2().hashToPoint(id);
        return Qid.multiplyPoint(masterKey);
    }

    public static Pair<ECPoint, byte[]> encrypt(IBESystemParams systemParams, byte[] id, byte[] message) {
        BigInteger r = Utils.generateRandomPositiveBigInteger(systemParams.getOrder());
        return encrypt(systemParams, id, message, r);
    }

    public static Pair<ECPoint, byte[]> encrypt(IBESystemParams systemParams, byte[] id, byte[] message, BigInteger r) {
        ECPoint qid = systemParams.getGroup2().hashToPoint(id);

        ECPoint P = systemParams.getGroup1Generator();
        ECPoint u = P.multiplyPoint(r);

        ExtensionFieldElement gID = systemParams.pair(systemParams.getPublicKey(), qid).exponentiate(r);
        byte[] V = Utils.byteArraysXOR(systemParams.getHashDigest(gID.toByteArray(), message.length), message);

        return new Pair<>(u, V);
    }

    public static byte[] decrypt(IBESystemParams systemParams, Pair<ECPoint, byte[]> ciphertext, ECPoint privateKey) {
        byte[] digest = systemParams.getHashDigest(systemParams.pair(ciphertext.getFirstElement(), privateKey)
                .toByteArray(), ciphertext.getSecondElement().length);
        return Utils.byteArraysXOR(ciphertext.getSecondElement(), digest);
    }
}