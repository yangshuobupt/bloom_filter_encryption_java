package ch.krmpoti.master;

public abstract class Pairing<T> {

    protected T pairing;

    public Pairing(T pairing) {
        this.pairing = pairing;
    }

    abstract ExtensionFieldElement pair(ECPoint point1, ECPoint point2);

    abstract EllipticCurve getGroup1();

    abstract EllipticCurve getGroup2();

    public T getPairing() {
        return pairing;
    }

}
