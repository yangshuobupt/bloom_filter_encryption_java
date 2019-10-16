package ch.krmpoti.master;

public class ParentKeyNotAvailableException extends Exception {

    public ParentKeyNotAvailableException() {}

    public ParentKeyNotAvailableException(String message) {
        super(message);
    }

    public ParentKeyNotAvailableException(Throwable cause) {
        super(cause);
    }

    public ParentKeyNotAvailableException(String message, Throwable cause) {
        super(message, cause);
    }

}