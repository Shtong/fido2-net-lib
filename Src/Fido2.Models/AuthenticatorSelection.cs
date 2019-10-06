using Fido2NetLib.Objects;
using Newtonsoft.Json;

namespace Fido2NetLib
{
    /// <summary>
    /// WebAuthn Relying Parties may use the AuthenticatorSelectionCriteria dictionary to specify their requirements regarding authenticator attributes.
    /// </summary>
    public class AuthenticatorSelection
    {
        /// <summary>
        /// If this member is present, eligible authenticators are filtered to only authenticators attached with the specified §5.4.5 Authenticator Attachment enumeration (enum AuthenticatorAttachment).
        /// </summary>
        [JsonProperty("authenticatorAttachment", NullValueHandling = NullValueHandling.Ignore)]
        public AuthenticatorAttachment? AuthenticatorAttachment { get; set; }

        /// <summary>
        /// This member describes the Relying Parties' requirements regarding resident credentials. If the parameter is set to true, the authenticator MUST create a client-side-resident public key credential source when creating a public key credential.
        /// </summary>
        [JsonProperty("requireResidentKey")]
        public bool RequireResidentKey { get; set; }

        /// <summary>
        /// This member describes the Relying Party's requirements regarding user verification for the create() operation. Eligible authenticators are filtered to only those capable of satisfying this requirement.
        /// </summary>
        [JsonProperty("userVerification")]
        public UserVerificationRequirement UserVerification { get; set; }

        public static AuthenticatorSelection Default => new AuthenticatorSelection
        {
            AuthenticatorAttachment = null,
            RequireResidentKey = false,
            UserVerification = UserVerificationRequirement.Preferred
        };
    }
}
