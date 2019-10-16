package ch.krmpoti.master;

import java.math.BigInteger;

public abstract class ExtensionFieldElement<T> {

    protected T extensionFieldElement;

    public ExtensionFieldElement(T extensionFieldElement) {
        this.extensionFieldElement = extensionFieldElement;
    }

    abstract ExtensionFieldElement exponentiate(BigInteger exponent);

    abstract ExtensionFieldElement multiply(BigInteger factor);

    abstract ExtensionFieldElement multiply(ExtensionFieldElement element);

    abstract ExtensionFieldElement add(ExtensionFieldElement element);

    abstract ExtensionFieldElement divide(ExtensionFieldElement element);

    abstract byte[] toByteArray();

    public T getExtensionFieldElement() {
        return extensionFieldElement;
    }

}
