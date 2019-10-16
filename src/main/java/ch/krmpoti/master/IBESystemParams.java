package ch.krmpoti.master;

import java.math.BigInteger;
import java.util.HashMap;

public abstract class IBESystemParams {

    private HashMap<String, ECPoint> parameters = new HashMap<>();

    abstract void setPublicKey(ECPoint publicKey);
    abstract ECPoint getPublicKey();
    abstract byte[] getHashDigest(byte[] input, int outputSize);

    abstract ExtensionFieldElement pair(ECPoint point1, ECPoint point2);

    abstract EllipticCurve getGroup1();
    abstract ECPoint getGroup1Generator();

    abstract EllipticCurve getGroup2();
    abstract ECPoint getGroup2Generator();

    abstract BigInteger getOrder();

    public void setParameter(String key, ECPoint value) {
        this.parameters.put(key + "_general", value);
    }

    public void setParameter(String key, String area, ECPoint value) {
        if (area == null || "".equals(area.trim())) {
            setParameter(key, value);
            return;
        }
        this.parameters.put(key + "_" + area, value);
    }

    public ECPoint getParameter(String key) {
        return this.parameters.get(key + "_general");
    }

    public ECPoint getParameter(String key, String area) {
        if (area == null || "".equals(area.trim())) {
            return getParameter(key);
        }
        return this.parameters.get(key + "_" + area);
    }

    public boolean containsParameter(String key) {
        return this.parameters.containsKey(key + "_general");
    }

    public boolean containsParameter(String key, String area) {
        if (area == null || "".equals(area.trim())) {
            return containsParameter(key);
        }
        return this.parameters.containsKey(key + "_" + area);
    }
}
