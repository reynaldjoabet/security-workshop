package token;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.nativesso.DeviceSecret;
import net.minidev.json.JSONObject;

import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;


/**
 * ID token, access token and optional refresh token.
 */
public final class OIDCTokens extends Tokens {


	/**
	 * The ID token serialised to a JWT, {@code null} if not specified.
	 */
	private final JWT idToken;


	/**
	 * The ID token as raw string (for more efficient serialisation),
	 * {@code null} if not specified.
	 */
	private final String idTokenString;


	/**
	 * Device secret for OpenID Connect native SSO, {@code null} if not
	 * specified.
	 */
	private final DeviceSecret deviceSecret;
	
	
	/**
	 * Creates a new OpenID Connect tokens instance.
	 *
	 * @param idToken      The ID token. Must not be {@code null}.
	 * @param accessToken  The access token. Must not be {@code null}.
	 * @param refreshToken The refresh token, {@code null} if none.
	 */
	public OIDCTokens(final JWT idToken, final AccessToken accessToken, final RefreshToken refreshToken) {
		this(idToken, accessToken, refreshToken, null);
	}


	/**
	 * Creates a new OpenID Connect tokens instance.
	 *
	 * @param idToken      The ID token. Must not be {@code null}.
	 * @param accessToken  The access token. Must not be {@code null}.
	 * @param refreshToken The refresh token, {@code null} if none.
	 * @param deviceSecret The device secret for OpenID Connect native SSO,
	 *                     {@code null} if not specified.
	 */
	public OIDCTokens(final JWT idToken,
			  final AccessToken accessToken,
			  final RefreshToken refreshToken,
			  final DeviceSecret deviceSecret) {
		super(accessToken, refreshToken);
		this.idToken = Objects.requireNonNull(idToken);
		idTokenString = null;
		this.deviceSecret = deviceSecret;
	}
	
	
	/**
	 * Creates a new OpenID Connect tokens instance.
	 *
	 * @param idTokenString The ID token string. Must not be {@code null}.
	 * @param accessToken   The access token. Must not be {@code null}.
	 * @param refreshToken  The refresh token, {@code null} if none.
	 */
	public OIDCTokens(final String idTokenString, final AccessToken accessToken, final RefreshToken refreshToken) {
		this(idTokenString, accessToken, refreshToken, null);
	}


	/**
	 * Creates a new OpenID Connect tokens instance.
	 *
	 * @param idTokenString The ID token string. Must not be {@code null}.
	 * @param accessToken   The access token. Must not be {@code null}.
	 * @param refreshToken  The refresh token, {@code null} if none.
	 * @param deviceSecret  The device secret for OpenID Connect native
	 *                      SSO, {@code null} if not specified.
	 */
	public OIDCTokens(final String idTokenString,
			  final AccessToken accessToken,
			  final RefreshToken refreshToken,
			  final DeviceSecret deviceSecret) {
		super(accessToken, refreshToken);
		this.idTokenString = Objects.requireNonNull(idTokenString);
		idToken = null;
		this.deviceSecret = deviceSecret;
	}
	
	
	/**
	 * Creates a new OpenID Connect tokens instance without an ID token.
	 * Intended for token responses from a refresh token grant where the ID
	 * token is optional.
	 *
	 * @param accessToken  The access token. Must not be {@code null}.
	 * @param refreshToken The refresh token, {@code null} if none.
	 */
	public OIDCTokens(final AccessToken accessToken, final RefreshToken refreshToken) {
		this(accessToken, refreshToken, null);
	}


	/**
	 * Creates a new OpenID Connect tokens instance without an ID token.
	 * Intended for token responses from a refresh token grant where the ID
	 * token is optional.
	 *
	 * @param accessToken  The access token. Must not be {@code null}.
	 * @param refreshToken The refresh token, {@code null} if none.
	 * @param deviceSecret The device secret for OpenID Connect native SSO,
	 *                     {@code null} if not specified.
	 */
	public OIDCTokens(final AccessToken accessToken,
			  final RefreshToken refreshToken,
			  final DeviceSecret deviceSecret) {

		super(accessToken, refreshToken);
		this.idToken = null;
		this.idTokenString = null;
		this.deviceSecret = deviceSecret;
	}


	/**
	 * Gets the ID token.
	 *
	 * @return The ID token, {@code null} if none or if parsing to a JWT
	 *         failed.
	 */
	public JWT getIDToken() {

		if (idToken != null)
			return idToken;

		if (idTokenString != null) {

			try {
				return JWTParser.parse(idTokenString);

			} catch (java.text.ParseException e) {

				return null;
			}
		}

		return null;
	}


	/**
	 * Gets the ID token string.
	 *
	 * @return The ID token string, {@code null} if none or if
	 *         serialisation to a string failed.
	 */
	public String getIDTokenString() {

		if (idTokenString != null)
			return idTokenString;

		if (idToken != null) {

			// Reproduce originally parsed string if any
			if (idToken.getParsedString() != null)
				return idToken.getParsedString();

			try {
				return idToken.serialize();

			} catch(IllegalStateException e) {

				return null;
			}
		}

		return null;
	}


	/**
	 * Returns the device secret for native SSO.
	 *
	 * @return The device secret, {@code null} if not specified.
	 */
	public DeviceSecret getDeviceSecret() {

		return deviceSecret;
	}


	@Override
	public Set<String> getParameterNames() {

		Set<String> paramNames = new HashSet<>(super.getParameterNames());
		if (idToken != null || idTokenString != null) {
			paramNames.add("id_token");
		}
		if (deviceSecret != null) {
			paramNames.add("device_secret");
		}
		return Collections.unmodifiableSet(paramNames);
	}


	@Override
	public JSONObject toJSONObject() {

		JSONObject o = super.toJSONObject();
		if (getIDTokenString() != null) {
			o.put("id_token", getIDTokenString());
		}
		if (deviceSecret != null) {
			o.put("device_secret", deviceSecret.getValue());
		}
		return o;
	}


	/**
	 * Parses an OpenID Connect tokens instance from the specified JSON
	 * object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The OpenID Connect tokens.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an
	 *                        OpenID Connect tokens instance.
	 */
	public static OIDCTokens parse(final JSONObject jsonObject)
		throws ParseException {
		
		AccessToken accessToken = AccessToken.parse(jsonObject);
		
		RefreshToken refreshToken = RefreshToken.parse(jsonObject);

		DeviceSecret deviceSecret = null;
		if (jsonObject.get("device_secret") != null) {
			deviceSecret = DeviceSecret.parse(JSONObjectUtils.getNonBlankString(jsonObject, "device_secret"));
		}
		
		if (jsonObject.get("id_token") != null) {
			JWT idToken;
			try {
				idToken = JWTParser.parse(JSONObjectUtils.getNonBlankString(jsonObject, "id_token"));
			} catch (java.text.ParseException e) {
				throw new ParseException("Couldn't parse ID token: " + e.getMessage(), e);
			}

			return new OIDCTokens(idToken, accessToken, refreshToken, deviceSecret);
			
		} else {
			// Likely a token response from a refresh token grant without an ID token
			return new OIDCTokens(accessToken, refreshToken, deviceSecret);
		}
	}
}
