using Newtonsoft.Json;

namespace Fido2NetLib
{
    /// <summary>
    /// PublicKeyCredentialRpEntity 
    /// </summary>
    public class PublicKeyCredentialRelyingPartyEntity
    {
        public PublicKeyCredentialRelyingPartyEntity(string id, string name, string icon)
        {
            Name = name;
            Id = id;
            Icon = icon;
        }

        /// <summary>
        /// A unique identifier for the Relying Party entity, which sets the RP ID.
        /// </summary>
        [JsonProperty("id")]
        public string Id { get; set; }

        /// <summary>
        /// A human-readable name for the entity. Its function depends on what the PublicKeyCredentialEntity represents:
        /// </summary>
        [JsonProperty("name")]
        public string Name { get; set; }

        // TODO : What's this? Should we keep it?
        [JsonProperty("icon", DefaultValueHandling = DefaultValueHandling.Ignore)]
        public string Icon { get; set; }
    }
}
