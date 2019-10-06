using Fido2NetLib.Objects;
using Newtonsoft.Json;
using Shouldly;
using Xunit;

namespace Fido2.Tests.Models.Objects
{
    public class AuthenticatorAttachmentTests
    {
        [Fact]
        public void IsSerializable()
        {
            var value = AuthenticatorAttachment.CrossPlatform;
            var serialized = JsonConvert.SerializeObject(value);
            var deserialized = JsonConvert.DeserializeObject<AuthenticatorAttachment>(serialized);

            serialized.ShouldBe("\"cross-platform\"");
            deserialized.ShouldBe(AuthenticatorAttachment.CrossPlatform);
        }
    }
}
