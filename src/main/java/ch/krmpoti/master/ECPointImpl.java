package ch.krmpoti.master;

import java.math.BigInteger;

public class ECPointImpl extends ECPoint<iaik.security.ec.math.curve.ECPoint> {

    public ECPointImpl(iaik.security.ec.math.curve.ECPoint point) {
        super(point);
    }

    @Override
    public ECPoint multiplyPoint(BigInteger factor) {
        return new ECPointImpl(this.point.multiplyPoint(factor));
    }

    @Override
    public ECPoint addPoint(ECPoint point) {
        return new ECPointImpl(this.point.addPoint((iaik.security.ec.math.curve.ECPoint) point.getPoint()));
    }

}
