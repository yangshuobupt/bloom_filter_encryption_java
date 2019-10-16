package ch.krmpoti.master;

import java.math.BigInteger;

public class ExtensionFieldElementImpl extends ExtensionFieldElement<iaik.security.ec.math.field.ExtensionFieldElement> {

    public ExtensionFieldElementImpl(iaik.security.ec.math.field.ExtensionFieldElement extensionFieldElement) {
        super(extensionFieldElement);
    }

    @Override
    ExtensionFieldElement exponentiate(BigInteger exponent) {
        return new ExtensionFieldElementImpl(extensionFieldElement.exponentiate(exponent));
    }

    @Override
    ExtensionFieldElement multiply(BigInteger factor) {
        return new ExtensionFieldElementImpl(extensionFieldElement.multiply(factor));
    }

    @Override
    ExtensionFieldElement multiply(ExtensionFieldElement element) {
        return new ExtensionFieldElementImpl(extensionFieldElement
                .multiply((iaik.security.ec.math.field.ExtensionFieldElement) element.getExtensionFieldElement()));
    }

    @Override
    ExtensionFieldElement add(ExtensionFieldElement element) {
        return new ExtensionFieldElementImpl(extensionFieldElement
                .add((iaik.security.ec.math.field.ExtensionFieldElement) element.getExtensionFieldElement()));
    }

    @Override
    ExtensionFieldElement divide(ExtensionFieldElement element) {
        return new ExtensionFieldElementImpl(extensionFieldElement
                .divide((iaik.security.ec.math.field.ExtensionFieldElement) element.getExtensionFieldElement()));
    }

    @Override
    byte[] toByteArray() {
        return extensionFieldElement.toByteArray();
    }
}
