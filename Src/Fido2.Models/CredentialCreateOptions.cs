﻿using Fido2NetLib.Objects;
using Newtonsoft.Json;
using System.Collections.Generic;

namespace Fido2NetLib
{
    public class CredentialCreateOptions : Fido2ResponseBase
    {
        /// <summary>
        /// 
        /// This member contains data about the Relying Party responsible for the request.
        /// Its value’s name member is required.
        /// Its value’s id member specifies the relying party identifier with which the credential should be associated.If omitted, its value will be the CredentialsContainer object’s relevant settings object's origin's effective domain.
        /// </summary>
        [JsonProperty("rp")]
        public PublicKeyCredentialRelyingPartyEntity Rp { get; set; }

        /// <summary>
        /// This member contains data about the user account for which the Relying Party is requesting attestation. 
        /// Its value’s name, displayName and id members are required.
        /// </summary>
        [JsonProperty("user")]
        public Fido2User User { get; set; }

        /// <summary>
        /// Must be generated by the Server (Relying Party)
        /// </summary>
        [JsonProperty("challenge")]
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] Challenge { get; set; }

        /// <summary>
        /// This member contains information about the desired properties of the credential to be created. The sequence is ordered from most preferred to least preferred. The platform makes a best-effort to create the most preferred credential that it can.
        /// </summary>
        [JsonProperty("pubKeyCredParams")]
        public List<PublicKeyCredentialsParameters> PubKeyCredParams { get; set; }

        /// <summary>
        /// This member specifies a time, in milliseconds, that the caller is willing to wait for the call to complete. This is treated as a hint, and MAY be overridden by the platform.
        /// </summary>
        [JsonProperty("timeout")]
        public long Timeout { get; set; }

        /// <summary>
        /// This member is intended for use by Relying Parties that wish to express their preference for attestation conveyance.The default is none.
        /// </summary>
        [JsonProperty("attestation")]
        public AttestationConveyancePreference Attestation { get; set; } = AttestationConveyancePreference.None;
        
        /// <summary>
        /// This member is intended for use by Relying Parties that wish to select the appropriate authenticators to participate in the create() operation.
        /// </summary>
        [JsonProperty("authenticatorSelection")]
        public AuthenticatorSelection AuthenticatorSelection { get; set; }

        /// <summary>
        /// This member is intended for use by Relying Parties that wish to limit the creation of multiple credentials for the same account on a single authenticator.The client is requested to return an error if the new credential would be created on an authenticator that also contains one of the credentials enumerated in this parameter.
        /// </summary>
        [JsonProperty("excludeCredentials")]
        public List<PublicKeyCredentialDescriptor> ExcludeCredentials { get; set; }

        /// <summary>
        /// This OPTIONAL member contains additional parameters requesting additional processing by the client and authenticator. For example, if transaction confirmation is sought from the user, then the prompt string might be included as an extension.
        /// </summary>
        [JsonProperty("extensions", NullValueHandling = NullValueHandling.Ignore)]
        public AuthenticationExtensionsClientInputs Extensions { get; set; }

        public static CredentialCreateOptions Create(Fido2Configuration config, byte[] challenge, Fido2User user, AuthenticatorSelection authenticatorSelection, AttestationConveyancePreference attestationConveyancePreference, List<PublicKeyCredentialDescriptor> excludeCredentials, AuthenticationExtensionsClientInputs extensions)
        {
            return new CredentialCreateOptions
            {
                Status = "ok",
                ErrorMessage = string.Empty,
                Challenge = challenge,
                Rp = new PublicKeyCredentialRelyingPartyEntity(config.ServerDomain, config.ServerName, config.ServerIcon),
                Timeout = config.Timeout,
                User = user,
                PubKeyCredParams = new List<PublicKeyCredentialsParameters>()
                {
                    // Add additional as appropriate
                    ES256,
                    RS256,
                    PS256,
                    ES384,
                    RS384,
                    PS384,
                    ES512,
                    RS512,
                    PS512,
                },
                AuthenticatorSelection = authenticatorSelection,
                Attestation = attestationConveyancePreference,
                ExcludeCredentials = excludeCredentials ?? new List<PublicKeyCredentialDescriptor>(),
                Extensions = extensions
            };
        }

        public string ToJson()
        {
            return JsonConvert.SerializeObject(this);
        }

        public static CredentialCreateOptions FromJson(string json)
        {
            return JsonConvert.DeserializeObject<CredentialCreateOptions>(json);
        }

        private static PublicKeyCredentialsParameters ES256 = new PublicKeyCredentialsParameters()
        {
            // External authenticators support the ES256 algorithm
            Type = PublicKeyCredentialType.PublicKey,
            Alg = -7
        };
        private static PublicKeyCredentialsParameters ES384 = new PublicKeyCredentialsParameters()
        {
            Type = PublicKeyCredentialType.PublicKey,
            Alg = -35
        };
        private static PublicKeyCredentialsParameters ES512 = new PublicKeyCredentialsParameters()
        {
            Type = PublicKeyCredentialType.PublicKey,
            Alg = -36
        };
        private static PublicKeyCredentialsParameters RS256 = new PublicKeyCredentialsParameters()
        {
            // Windows Hello supports the RS256 algorithm
            Type = PublicKeyCredentialType.PublicKey,
            Alg = -257
        };
        private static PublicKeyCredentialsParameters RS384 = new PublicKeyCredentialsParameters()
        {
            Type = PublicKeyCredentialType.PublicKey,
            Alg = -258
        };
        private static PublicKeyCredentialsParameters RS512 = new PublicKeyCredentialsParameters()
        {
            Type = PublicKeyCredentialType.PublicKey,
            Alg = -259
        };
        private static PublicKeyCredentialsParameters PS256 = new PublicKeyCredentialsParameters()
        {
            Type = PublicKeyCredentialType.PublicKey,
            Alg = -37
        };
        private static PublicKeyCredentialsParameters PS384 = new PublicKeyCredentialsParameters()
        {
            Type = PublicKeyCredentialType.PublicKey,
            Alg = -38
        };
        private static PublicKeyCredentialsParameters PS512 = new PublicKeyCredentialsParameters()
        {
            Type = PublicKeyCredentialType.PublicKey,
            Alg = -39
        };
    }
}
