package ch.krmpoti.master;

public class Triple<U, V, Z> {

    private U u;
    private V v;
    private Z z;

    public Triple(U u, V v, Z z) {
        this.u = u;
        this.v = v;
        this.z = z;
    }

    public U getFirstElement() {
        return u;
    }

    public void setFirstElement(U u) {
        this.u = u;
    }

    public V getSecondElement() {
        return v;
    }

    public void setSecondElement(V v) {
        this.v = v;
    }

    public Z getThirdElement() {
        return z;
    }

    public void setThirdElement(Z z) {
        this.z = z;
    }
}
