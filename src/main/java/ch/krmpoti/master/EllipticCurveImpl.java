package ch.krmpoti.master;

import java.math.BigInteger;

public class EllipticCurveImpl extends EllipticCurve<iaik.security.ec.math.curve.EllipticCurve> {

    public EllipticCurveImpl(iaik.security.ec.math.curve.EllipticCurve ellipticCurve) {
        super(ellipticCurve);
    }

    @Override
    public ECPoint hashToPoint(byte[] bytes) {
        return new ECPointImpl(ellipticCurve.hashToPoint(bytes));
    }

    @Override
    public ECPoint getGenerator() {
        return new ECPointImpl(ellipticCurve.getGenerator());
    }

    @Override
    public ECPoint getNeutralPoint() {
        return new ECPointImpl(ellipticCurve.getNeutralPoint());
    }

    @Override
    BigInteger getOrder() {
        return ellipticCurve.getOrder();
    }
}