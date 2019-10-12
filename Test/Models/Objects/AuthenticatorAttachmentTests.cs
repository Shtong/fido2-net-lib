using Fido2NetLib.Objects;
using Newtonsoft.Json;
using Shouldly;
using Xunit;

namespace Fido2.Models.Objects
{
    public class AuthenticatorAttachmentTests : Fido2TestBase
    {
        [Fact]
        public void IsSerializable()
        {
            AuthenticatorAttachment value = AuthenticatorAttachment.CrossPlatform;
            string serialized = JsonConvert.SerializeObject(value);
            AuthenticatorAttachment deserialized = JsonConvert.DeserializeObject<AuthenticatorAttachment>(serialized);

            serialized.ShouldBe("\"cross-platform\"");
            deserialized.ShouldBe(AuthenticatorAttachment.CrossPlatform);
        }
    }
}
