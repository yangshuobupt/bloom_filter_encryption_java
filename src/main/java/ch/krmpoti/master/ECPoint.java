package ch.krmpoti.master;

import java.math.BigInteger;

public abstract class ECPoint<T> {

    protected T point;

    public ECPoint(T point) {
        this.point = point;
    }

    abstract public ECPoint multiplyPoint(BigInteger factor);

    abstract public ECPoint addPoint(ECPoint point);

    public T getPoint() {
        return point;
    }

    public int hashCode() {
        return point.hashCode();
    }
}
