using System.Security.Cryptography;
using Chaos.NaCl;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Shouldly;
using Xunit;

namespace Fido2.Tests.Objects
{
    public class AttestedCredentialDataTests : Fido2TestBase
    {
        [Fact]
        public void GeneratesCorrectDataWithES256()
        {
            using (ECDsaCng ecdsa = MakeECDsa(COSE.Algorithm.ES256, COSE.EllipticCurve.P256))
            {
                ECParameters ecparams = ecdsa.ExportParameters(true);
                CredentialPublicKey cpk = MakeCredentialPublicKey(
                    COSE.Algorithm.ES256,
                    COSE.EllipticCurve.P256,
                    ecparams.Q.X,
                    ecparams.Q.Y);

                VerifyCredentialData(cpk);
            }
        }

        [Fact]
        public void GeneratesCorrectDataWithRSA()
        {
            using (var rsa = new RSACng())
            {
                RSAParameters rsaparams = rsa.ExportParameters(true);
                CredentialPublicKey cpk = MakeCredentialPublicKey(
                    COSE.Algorithm.RS256,
                    rsaparams.Modulus,
                    rsaparams.Exponent);

                VerifyCredentialData(cpk);
            }
        }

        [Fact]
        public void GeneratesCorrectDataWithOKP()
        {
            MakeEdDSA(out var publicKey);
            CredentialPublicKey cpk = MakeCredentialPublicKey(
                COSE.Algorithm.EdDSA,
                COSE.EllipticCurve.Ed25519,
                publicKey);

            VerifyCredentialData(cpk);
        }

        [Fact]
        public void PackedRawDataToAttestedCredential()
        {
            var rawData = ReadTestDataFromFile<AuthenticatorAttestationRawResponse>("./attestationResultsPacked.json");
            var response = AuthenticatorAttestationResponse.Parse(rawData);

            byte[] authDataBytes = response.AttestationObject.AuthData;

            var authData = new AuthenticatorData(authDataBytes);
            authData.ToByteArray().ShouldBe(authDataBytes);

            var attestedCredentialBytes = authData.AttestedCredentialData.ToByteArray();
            var attestedCredential = new AttestedCredentialData(attestedCredentialBytes);
            attestedCredential.ToByteArray().ShouldBe(attestedCredentialBytes);
        }

        private void VerifyCredentialData(CredentialPublicKey credentialPublicKey)
        {
            var acdFromConst = new AttestedCredentialData(_aaGuid, _credentialId, credentialPublicKey);
            var acdBytes = acdFromConst.ToByteArray();
            var acdFromBytes = new AttestedCredentialData(acdBytes);

            acdFromBytes.ToByteArray().ShouldBe(acdFromConst.ToByteArray());
        }

        private void MakeEdDSA(out byte[] publicKey)
        {
            byte[] privateKeySeed = CreateRandomBytes(32);
            Ed25519.KeyPairFromSeed(out publicKey, out _, privateKeySeed);
        }
    }
}
