package nativesso;


import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.Token;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import java.util.HashSet;
import java.util.Set;


/**
 * {@link Token} representation of a device secret.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Native SSO for Mobile Apps 1.0
 * </ul>
 */
@Immutable
public final class DeviceSecretToken extends Token {


	private static final long serialVersionUID = -5834546200975074494L;


	/**
	 * Creates a new device secret token.
	 *
	 * @param deviceSecret The device secret. Must not be {@code null}.
	 */
	public DeviceSecretToken(final DeviceSecret deviceSecret) {
	
		super(deviceSecret.getValue());
	}


	/**
	 * Returns the device secret.
	 *
	 * @return The device secret.
	 */
	public DeviceSecret getDeviceSecret() {

		return new DeviceSecret(getValue());
	}


	@Override
	public Set<String> getParameterNames() {

		Set<String> paramNames = new HashSet<>(getCustomParameters().keySet());
		paramNames.add("device_secret");
		return paramNames;
	}


	@Override
	public JSONObject toJSONObject() {

		JSONObject o = new JSONObject();
		o.putAll(getCustomParameters());
		o.put("device_secret", getValue());
		return o;
	}


	/**
	 * Parses a device secret token from a JSON object access token
	 * response.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The device secret token, {@code null} if not found.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a
	 *                        device secret token.
	 */
	public static DeviceSecretToken parse(final JSONObject jsonObject)
		throws ParseException {

		String value = JSONObjectUtils.getString(jsonObject, "device_secret", null);
		
		if (value == null) return null;

		try {
			return new DeviceSecretToken(new DeviceSecret(value));
		} catch (Exception e) {
			throw new ParseException("Illegal device secret", e);
		}
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof DeviceSecretToken &&
		       this.toString().equals(object.toString());
	}
}
