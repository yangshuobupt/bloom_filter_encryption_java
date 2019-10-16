package ch.krmpoti.master;

public class PairingImpl extends Pairing<iaik.security.ec.math.curve.Pairing> {

    public PairingImpl(iaik.security.ec.math.curve.Pairing pairing) {
        super(pairing);
    }

    @Override
    ExtensionFieldElement pair(ECPoint point1, ECPoint point2) {
        return new ExtensionFieldElementImpl(
                pairing.pair((iaik.security.ec.math.curve.ECPoint) point1.getPoint(),
                        (iaik.security.ec.math.curve.ECPoint) point2.getPoint()));
    }

    @Override
    EllipticCurve getGroup1() {
        return new EllipticCurveImpl(pairing.getGroup1());
    }

    @Override
    EllipticCurve getGroup2() {
        return new EllipticCurveImpl(pairing.getGroup2());
    }
}
