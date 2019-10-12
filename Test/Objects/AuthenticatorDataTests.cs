using System.Security.Cryptography;
using System.Text;
using Fido2NetLib.Objects;
using PeterO.Cbor;
using Shouldly;
using Xunit;

namespace Fido2.Objects
{
    public class AuthenticatorDataTests : Fido2TestBase
    {
        [Fact]
        public void SimpleInitialization()
        {
            // Initialize test data
            var flags = AuthenticatorFlags.AT | AuthenticatorFlags.ED | AuthenticatorFlags.UP | AuthenticatorFlags.UV;
            const ushort signCount = 0xf1d0;

            byte[] rpIdHash;
            using(var sha = SHA256.Create())
            {
                rpIdHash = sha.ComputeHash(Encoding.UTF8.GetBytes("fido2.azurewebsites.net/"));
            }

            ECDsaCng ecdsa = MakeECDsa(COSE.Algorithm.ES256, COSE.EllipticCurve.P256);
            ECParameters ecparams = ecdsa.ExportParameters(true);
            CredentialPublicKey cpk = MakeCredentialPublicKey(
                COSE.Algorithm.ES256,
                COSE.EllipticCurve.P256,
                ecparams.Q.X,
                ecparams.Q.Y);
            var acd = new AttestedCredentialData(_aaGuid, _credentialId, cpk);

            var extBytes = CBORObject.NewMap().Add("testing", true).EncodeToBytes();
            var exts = new Extensions(extBytes);

            // Execute
            var result = new AuthenticatorData(rpIdHash, flags, signCount, acd, exts);

            // Assert
            result.RpIdHash.ShouldBe(rpIdHash);
            result.HasAttestedCredentialData.ShouldBeTrue();
            result.UserPresent.ShouldBeTrue();
            result.UserVerified.ShouldBeTrue();
            result.HasExtensionsData.ShouldBeTrue();
            result.SignCount.ShouldBe(signCount);
            result.AttestedCredentialData.ToByteArray().ShouldBe(acd.ToByteArray());
            result.Extensions.GetBytes().ShouldBe(extBytes);
        }
    }
}
