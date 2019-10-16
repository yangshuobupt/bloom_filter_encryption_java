package ch.krmpoti.master;

import iaik.security.ec.math.curve.AtePairingOverBarretoNaehrigCurveFactory;
import iaik.security.ec.math.curve.PairingTypes;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

public final class HierarchicalIBE {

    private static final Logger LOGGER = Logger.getLogger(HierarchicalIBE.class.getName());

    private static final String GROUP_1 = "group1";
    private static final String GROUP_2 = "group2";

    public static Pair<IBESystemParams, ECPoint> setup(int depth, int k) {
        if (depth < 1) {
            throw new IllegalArgumentException("Provided tree depth has to be positive!");
        }
        IBESystemParams systemParams;

        systemParams = new IBESystemParamsImpl(
                new PairingImpl(AtePairingOverBarretoNaehrigCurveFactory.getPairing(PairingTypes.TYPE_3, k)));

        BigInteger alpha = Utils.generateRandomPositiveBigInteger(systemParams.getOrder());
        BigInteger delta = alpha;
        for (int i = 1; i <= 3; i++) {
            systemParams.setParameter(HIBEParam.G.withIndex(i), GROUP_1,
                    systemParams.getGroup1Generator().multiplyPoint(delta));
            systemParams.setParameter(HIBEParam.G.withIndex(i), GROUP_2,
                    systemParams.getGroup2Generator().multiplyPoint(delta));

            delta = Utils.generateRandomPositiveBigInteger(systemParams.getOrder());
        }
        for (int i = 1; i <= depth; i++) {
            delta = Utils.generateRandomPositiveBigInteger(systemParams.getOrder());
            systemParams.setParameter(HIBEParam.H.withIndex(i), GROUP_1,
                    systemParams.getGroup1Generator().multiplyPoint(delta));
            systemParams.setParameter(HIBEParam.H.withIndex(i), GROUP_2,
                    systemParams.getGroup2Generator().multiplyPoint(delta));
        }

        ECPoint masterKey = systemParams.getParameter(HIBEParam.G.withIndex(2), GROUP_1).multiplyPoint(alpha);

        return new Pair<>(systemParams, masterKey);
    }

    public static Triple<ECPoint, ECPoint, List<ECPoint>> extract(IBESystemParams systemParams,
                                                                  ECPoint masterKey,
                                                                  String id) {
        char[] idChars = new char[id.length()];
        id.getChars(0, id.length(), idChars, 0);

        BigInteger r = Utils.generateRandomPositiveBigInteger(systemParams.getOrder());
        ECPoint a0 = systemParams.getGroup1().getNeutralPoint();
        List<ECPoint> b = new ArrayList<>();

        for (int i = 1; i <= id.length(); i++) {
            if ("0".charAt(0) == idChars[i - 1]) {
                a0.addPoint(systemParams.getParameter(HIBEParam.H.withIndex(i), GROUP_1));
            } else {
                a0.addPoint(systemParams.getParameter(HIBEParam.H.withIndex(i), GROUP_1)
                        .multiplyPoint(BigInteger.valueOf(2)));
            }
        }
        a0.addPoint(systemParams.getParameter(HIBEParam.G.withIndex(3), GROUP_1));
        a0 = a0.multiplyPoint(r);
        a0.addPoint(masterKey);

        int i = id.length() + 1;
        while (systemParams.containsParameter(HIBEParam.H.withIndex(i), GROUP_1)) {
            b.add((systemParams.getParameter(HIBEParam.H.withIndex(i), GROUP_1)).multiplyPoint(r));
            i++;
        }

        return new Triple<>(a0, systemParams.getGroup1Generator().multiplyPoint(r), b);
    }

    public static Triple<ECPoint, ECPoint, List<ECPoint>> derive(IBESystemParams systemParams,
                                                      Triple<ECPoint, ECPoint, List<ECPoint>> parentPrivateKey,
                                                      String id) {
        char[] idChars = new char[id.length()];
        id.getChars(0, id.length(), idChars, 0);

        BigInteger t = Utils.generateRandomPositiveBigInteger(systemParams.getOrder());
        ECPoint a0 = systemParams.getGroup1().getNeutralPoint();
        List<ECPoint> b = new ArrayList<>();

        for (int i = 1; i <= id.length(); i++) {
            if ("0".charAt(0) == idChars[i - 1]) {
                a0.addPoint(systemParams.getParameter(HIBEParam.H.withIndex(i), GROUP_1));
            } else {
                a0.addPoint(systemParams.getParameter(HIBEParam.H.withIndex(i), GROUP_1)
                        .multiplyPoint(BigInteger.valueOf(2)));
            }
        }
        a0.addPoint(systemParams.getParameter(HIBEParam.G.withIndex(3), GROUP_1));
        a0 = a0.multiplyPoint(t);
        a0.addPoint(parentPrivateKey.getFirstElement());
        if ("0".charAt(0) == idChars[id.length() - 1]) {
            a0.addPoint(parentPrivateKey.getThirdElement().get(0));
        } else {
            a0.addPoint(parentPrivateKey.getThirdElement().get(0).multiplyPoint(BigInteger.valueOf(2)));
        }

        int i = id.length() + 1;
        int j = 1;
        while (systemParams.containsParameter(HIBEParam.H.withIndex(i), GROUP_1)) {
            b.add(systemParams.getParameter(HIBEParam.H.withIndex(i), GROUP_1)
                    .multiplyPoint(t)
                    .addPoint(parentPrivateKey.getThirdElement().get(j)));
            i++;
            j++;
        }

        return new Triple<>(a0, systemParams.getGroup1Generator().multiplyPoint(t).addPoint(parentPrivateKey.getSecondElement()), b);
    }

    public static Triple<ExtensionFieldElement, ECPoint, ECPoint> encrypt(IBESystemParams systemParams,
                                                                          String id,
                                                                          byte[] message) {
        char[] idChars = new char[id.length()];
        id.getChars(0, id.length(), idChars, 0);

        BigInteger s = Utils.generateRandomPositiveBigInteger(systemParams.getOrder());

        ExtensionFieldElement a = systemParams
                .pair(systemParams.getParameter(HIBEParam.G.withIndex(1), GROUP_1),
                        systemParams.getParameter(HIBEParam.G.withIndex(2), GROUP_2))
                .exponentiate(s)
                .multiply(new BigInteger(message));

        ECPoint b = systemParams.getGroup2Generator().multiplyPoint(s);

        ECPoint c = systemParams.getGroup2().getNeutralPoint();
        for (int i = 1; i <= id.length(); i++) {
            if ("0".charAt(0) == idChars[i - 1]) {
                c.addPoint(systemParams.getParameter(HIBEParam.H.withIndex(i), GROUP_2));
            } else {
                c.addPoint(systemParams.getParameter(HIBEParam.H.withIndex(i), GROUP_2)
                        .multiplyPoint(BigInteger.valueOf(2)));
            }
        }
        c.addPoint(systemParams.getParameter(HIBEParam.G.withIndex(3),GROUP_2));
        c = c.multiplyPoint(s);

        return new Triple<>(a, b, c);
    }

    public static byte[] decrypt(IBESystemParams systemParams,
                                 Triple<ExtensionFieldElement, ECPoint, ECPoint> ciphertext,
                                 Triple<ECPoint, ECPoint, List<ECPoint>> privateKey) {

        ExtensionFieldElement numerator = systemParams.pair(privateKey.getSecondElement(),
                ciphertext.getThirdElement());
        ExtensionFieldElement denominator = systemParams.pair(privateKey.getFirstElement(),
                ciphertext.getSecondElement());

        ExtensionFieldElement result = numerator.divide(denominator);

        if (ciphertext.getFirstElement() != null) {
            result.multiply(ciphertext.getFirstElement());
        }

        return result.toByteArray();
    }
}