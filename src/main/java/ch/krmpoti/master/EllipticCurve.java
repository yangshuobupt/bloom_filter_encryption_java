package ch.krmpoti.master;

import java.math.BigInteger;

public abstract class EllipticCurve<T> {

    protected T ellipticCurve;

    public EllipticCurve(T ellipticCurve) {
        this.ellipticCurve = ellipticCurve;
    }

    abstract ECPoint hashToPoint(byte[] bytes);

    abstract ECPoint getGenerator();

    abstract BigInteger getOrder();

    abstract ECPoint getNeutralPoint();

    public T getEllipticCurve() {
        return ellipticCurve;
    }

}
