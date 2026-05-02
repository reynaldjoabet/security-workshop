package nativesso;

import com.nimbusds.oauth2.sdk.Scope;
import net.jcip.annotations.Immutable;


/**
 * Device SSO scope value.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Native SSO for Mobile Apps 1.0
 * </ul>
 */
@Immutable
public class DeviceSSOScopeValue extends Scope.Value {


        /**
         * Informs the authorisation server that the client is making an OpenID
         * Connect Native SSO request.
         */
        public static final DeviceSSOScopeValue DEVICE_SSO = new DeviceSSOScopeValue("device_sso");


        private DeviceSSOScopeValue(String value) {
                super(value);
        }

}
