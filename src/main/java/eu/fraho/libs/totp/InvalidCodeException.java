package eu.fraho.libs.totp;

public class InvalidCodeException extends Exception {
    public InvalidCodeException() {
        super("The provided TOTP code is invalid");
    }
}
