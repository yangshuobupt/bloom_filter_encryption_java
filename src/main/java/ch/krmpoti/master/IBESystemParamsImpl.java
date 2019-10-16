package ch.krmpoti.master;

import java.math.BigInteger;

public class IBESystemParamsImpl extends IBESystemParams {

    private Pairing pairing;
    private ECPoint publicKey;

    public IBESystemParamsImpl(Pairing pairing) {
        this.pairing = pairing;
    }

    public Pairing getPairing() {
        return pairing;
    }

    public void setPairing(Pairing pairing) {
        this.pairing = pairing;
    }

    @Override
    public void setPublicKey(ECPoint publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public ECPoint getPublicKey() {
        return publicKey;
    }

    @Override
    public byte[] getHashDigest(byte[] input, int outputSize) {
        return Utils.getSHAKE256digest(input, outputSize);
    }

    @Override
    public BigInteger getOrder() {
        return pairing.getGroup1().getOrder();
    }

    @Override
    public EllipticCurve getGroup1() {
        return pairing.getGroup1();
    }

    @Override
    public ECPoint getGroup1Generator() {
        return getGroup1().getGenerator();
    }

    @Override
    public EllipticCurve getGroup2() {
        return pairing.getGroup2();
    }

    @Override
    public ECPoint getGroup2Generator() {
        return getGroup2().getGenerator();
    }

    @Override
    public ExtensionFieldElement pair(ECPoint point1, ECPoint point2) {
        return getGroup1().getEllipticCurve() == pairing.getGroup1().getEllipticCurve() ?
                pairing.pair(point1, point2) :
                pairing.pair(point2, point1);
    }
}
