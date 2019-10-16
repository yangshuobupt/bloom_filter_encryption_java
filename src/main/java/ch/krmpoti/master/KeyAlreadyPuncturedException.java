package ch.krmpoti.master;

public class KeyAlreadyPuncturedException extends Exception {

    public KeyAlreadyPuncturedException() {}

    public KeyAlreadyPuncturedException(String message) {
        super(message);
    }

    public KeyAlreadyPuncturedException(Throwable cause) {
        super(cause);
    }

    public KeyAlreadyPuncturedException(String message, Throwable cause) {
        super(message, cause);
    }

}