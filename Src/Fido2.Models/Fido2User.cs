using Newtonsoft.Json;

namespace Fido2NetLib
{
    public class Fido2User
    {
        /// <summary>
        /// Required. A human-friendly identifier for a user account. It is intended only for display, i.e., aiding the user in determining the difference between user accounts with similar displayNames. For example, "alexm", "alex.p.mueller@example.com" or "+14255551234". https://w3c.github.io/webauthn/#dictdef-publickeycredentialentity
        /// </summary>
        [JsonProperty("name")]
        public string Name { get; set; }

        /// <summary>
        /// The user handle of the user account entity. To ensure secure operation, authentication and authorization decisions MUST be made on the basis of this id member, not the displayName nor name members
        /// </summary>
        [JsonProperty("id")]
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] Id { get; set; }

        /// <summary>
        /// A human-friendly name for the user account, intended only for display. For example, "Alex P. Müller" or "田中 倫". The Relying Party SHOULD let the user choose this, and SHOULD NOT restrict the choice more than necessary.
        /// </summary>
        [JsonProperty("displayName")]
        public string DisplayName { get; set; }
    }
}
