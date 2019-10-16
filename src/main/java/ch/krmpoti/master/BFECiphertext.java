package ch.krmpoti.master;

public class BFECiphertext {

    private Pair<ECPoint, byte[][]> ciphertext;

    public BFECiphertext(ECPoint first, byte[][] second) {
        this.ciphertext = new Pair<>(first, second);
    }

    public ECPoint getFirstElement() {
        return ciphertext.getFirstElement();
    }

    public byte[][] getSecondElement() {
        return ciphertext.getSecondElement();
    }

    public void setFirstElement(ECPoint first) {
        this.ciphertext.setFirstElement(first);
    }

    public void setSecondElement(byte[][] second) {
        this.ciphertext.setSecondElement(second);
    }

}
