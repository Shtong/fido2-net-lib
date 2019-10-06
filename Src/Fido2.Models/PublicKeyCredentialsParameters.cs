using Fido2NetLib.Objects;
using Newtonsoft.Json;

namespace Fido2NetLib
{
    public class PublicKeyCredentialsParameters
    {
        /// <summary>
        /// The type member specifies the type of credential to be created.
        /// </summary>
        [JsonProperty("type")]
        public PublicKeyCredentialType Type { get; set; }

        /// <summary>
        /// The alg member specifies the cryptographic signature algorithm with which the newly generated credential will be used, and thus also the type of asymmetric key pair to be generated, e.g., RSA or Elliptic Curve.
        /// </summary>
        [JsonProperty("alg")]
        public long Alg { get; set; }
    }
}
