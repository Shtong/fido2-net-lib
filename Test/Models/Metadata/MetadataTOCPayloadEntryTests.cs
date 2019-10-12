using System;
using Fido2NetLib;
using Newtonsoft.Json;
using Shouldly;
using Xunit;

namespace Fido2.Models.Metadata
{
    public class MetadataTOCPayloadEntryTests : Fido2TestBase
    {
        [Fact]
        public void IsSerializable()
        {
            var input = new MetadataTOCPayloadEntry()
            {
                AaGuid = Guid.NewGuid().ToString(),
                MetadataStatement = new MetadataStatement
                {
                    AaGuid = Guid.NewGuid().ToString(),
                    Description = "Test entry",
                    AuthenticatorVersion = 1,
                    AssertionScheme = "abc123",
                    AuthenticationAlgorithm = 1,
                    Upv = new Version[] 
                    {
                        new Version("1.0.0.0") 
                    },
                    AttestationTypes = new ushort[] { 1 },
                    UserVerificationDetails = Array.Empty<VerificationMethodDescriptor[]>(),
                    AttestationRootCertificates = new string[] 
                    { 
                        "..." 
                    },
                },
                StatusReports = Array.Empty<StatusReport>(),
                TimeOfLastStatusChange = DateTime.UtcNow.ToString("o")
            };

            var serialized = JsonConvert.SerializeObject(input);
            var deserialized = JsonConvert.DeserializeObject<MetadataTOCPayloadEntry>(serialized);

            deserialized.AaGuid.ShouldBe(input.AaGuid);
        }
    }
}
