package ch.krmpoti.master;

public class Pair<U, V> {

    private U u;
    private V v;

    public Pair(U u, V v) {
        this.u = u;
        this.v = v;
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
}
