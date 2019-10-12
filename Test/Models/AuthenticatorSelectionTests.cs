using Fido2NetLib;
using Fido2NetLib.Objects;
using Newtonsoft.Json;
using Shouldly;
using Xunit;

namespace Fido2.Models
{
    public class AuthenticatorSelectionTests : Fido2TestBase
    {
        [Fact]
        public void IsSerializable()
        {
            var subject = new AuthenticatorSelection
            {
                UserVerification = UserVerificationRequirement.Discouraged
            };
            var serialized = JsonConvert.SerializeObject(subject);
            AuthenticatorSelection deserialized = JsonConvert.DeserializeObject<AuthenticatorSelection>(serialized);

            deserialized.UserVerification.ShouldBe(UserVerificationRequirement.Discouraged);
        }
    }
}
