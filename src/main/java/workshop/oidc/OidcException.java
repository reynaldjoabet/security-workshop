package workshop.oidc;

public class OidcException extends Exception {
	public OidcException(String msg) {
		super(msg);
	}

	public OidcException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
