using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Chaos.NaCl;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Newtonsoft.Json;
using PeterO.Cbor;
using Xunit;

namespace Fido2.Tests
{
    public class Fido2Tests : Fido2TestBase
    {
        [Fact]
        public void TestAuthenticatorDataPa2rsing()
        {
            var bs = new byte[] { 1, 2, 3 };
            CBORObject x = CBORObject.NewMap().Add("bytes", bs);
            var s = x["bytes"].GetByteString();

            Assert.Equal(s, bs);
        }

        [Theory]
        [InlineData(COSE.KeyType.EC2, COSE.Algorithm.ES256)]
        [InlineData(COSE.KeyType.EC2, COSE.Algorithm.ES384, COSE.EllipticCurve.P384)]
        [InlineData(COSE.KeyType.EC2, COSE.Algorithm.ES512, COSE.EllipticCurve.P521)]
        [InlineData(COSE.KeyType.RSA, COSE.Algorithm.RS256)]
        [InlineData(COSE.KeyType.RSA, COSE.Algorithm.RS384)]
        [InlineData(COSE.KeyType.RSA, COSE.Algorithm.RS512)]
        [InlineData(COSE.KeyType.RSA, COSE.Algorithm.PS256)]
        [InlineData(COSE.KeyType.RSA, COSE.Algorithm.PS384)]
        [InlineData(COSE.KeyType.RSA, COSE.Algorithm.PS512)]
        [InlineData(COSE.KeyType.OKP, COSE.Algorithm.EdDSA, COSE.EllipticCurve.Ed25519)]
        public async Task MakeAssertionResponse(COSE.KeyType kty, COSE.Algorithm alg, COSE.EllipticCurve crv = COSE.EllipticCurve.P256)
        {
            const string relyingParty = "fido2.azurewebsites.net";
            const ushort signCount = 0xf1d0;

            using (var sha = SHA256.Create())
            {

                CredentialPublicKey cpk = null;
                ECDsaCng ecdsa = null;
                RSACng rsa = null;
                byte[] expandedPrivateKey = null;
                switch (kty)
                {
                    case COSE.KeyType.EC2:
                        {
                            ecdsa = MakeECDsa(alg, crv);
                            ECParameters ecparams = ecdsa.ExportParameters(true);
                            cpk = MakeCredentialPublicKey(alg, crv, ecparams.Q.X, ecparams.Q.Y);
                            break;
                        }
                    case COSE.KeyType.RSA:
                        {
                            rsa = new RSACng();
                            RSAParameters rsaparams = rsa.ExportParameters(true);
                            cpk = MakeCredentialPublicKey(alg, rsaparams.Modulus, rsaparams.Exponent);
                            break;
                        }
                    case COSE.KeyType.OKP:
                        {
                            MakeEdDSA(out var publicKey, out expandedPrivateKey);
                            cpk = MakeCredentialPublicKey(alg, COSE.EllipticCurve.Ed25519, publicKey);
                            break;
                        }

                    default:
                        throw new ArgumentOutOfRangeException(nameof(kty), $"Missing or unknown kty {kty}");
                }

                // Create authenticator data
                byte[] authData = CreateAuthenticatorData(relyingParty, signCount, sha, cpk);

                // Create client data
                var challenge = CreateRandomBytes(128);
                var clientData = new
                {
                    Type = "webauthn.get",
                    Challenge = challenge,
                    Origin = relyingParty,
                };
                var clientDataJson = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(clientData));

                // Create the hashed version of client data
                var hashedClientDataJson = sha.ComputeHash(clientDataJson);
                byte[] hashedAuthData = new byte[authData.Length + hashedClientDataJson.Length];
                Buffer.BlockCopy(authData, 0, hashedAuthData, 0, authData.Length);
                Buffer.BlockCopy(hashedClientDataJson, 0, hashedAuthData, authData.Length, hashedClientDataJson.Length);

                // Sign client data
                byte[] signature = null;
                switch (kty)
                {
                    case COSE.KeyType.EC2:
                        {
                            signature = ecdsa.SignData(hashedAuthData, CryptoUtils.algMap[(int)alg]);
                            break;
                        }
                    case COSE.KeyType.RSA:
                        {
                            RSASignaturePadding padding;
                            switch (alg) // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
                            {
                                case COSE.Algorithm.PS256:
                                case COSE.Algorithm.PS384:
                                case COSE.Algorithm.PS512:
                                    padding = RSASignaturePadding.Pss;
                                    break;

                                case COSE.Algorithm.RS1:
                                case COSE.Algorithm.RS256:
                                case COSE.Algorithm.RS384:
                                case COSE.Algorithm.RS512:
                                    padding = RSASignaturePadding.Pkcs1;
                                    break;
                                default:
                                    throw new ArgumentOutOfRangeException(nameof(alg), $"Missing or unknown alg {alg}");
                            }
                            signature = rsa.SignData(hashedAuthData, CryptoUtils.algMap[(int)alg], padding);
                            break;
                        }
                    case COSE.KeyType.OKP:
                        {
                            signature = Ed25519.Sign(hashedAuthData, expandedPrivateKey);
                            break;
                        }

                    default:
                        throw new ArgumentOutOfRangeException(nameof(kty), $"Missing or unknown kty {kty}");
                }

                if (kty == COSE.KeyType.EC2)
                {
                    signature = EcDsaSigFromSig(signature, ecdsa.KeySize);
                }

                var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
                {
                    AuthenticatorData = authData,
                    Signature = signature,
                    ClientDataJson = clientDataJson,
                    UserHandle = CreateRandomBytes(16),
                };

                var lib = new Fido2NetLib.Fido2(new Fido2Configuration()
                {
                    ServerDomain = relyingParty,
                    ServerName = relyingParty,
                    Origin = relyingParty,
                });
                var existingCredentials = new List<PublicKeyCredentialDescriptor>();
                var cred = new PublicKeyCredentialDescriptor
                {
                    Type = PublicKeyCredentialType.PublicKey,
                    Id = new byte[] { 0xf1, 0xd0 }
                };
                existingCredentials.Add(cred);

                AssertionOptions options = lib.GetAssertionOptions(existingCredentials, null, null);
                options.Challenge = challenge;
                var response = new AuthenticatorAssertionRawResponse()
                {
                    Response = assertion,
                    Type = PublicKeyCredentialType.PublicKey,
                    Id = new byte[] { 0xf1, 0xd0 },
                    RawId = new byte[] { 0xf1, 0xd0 },
                };

                // This should not throw an exception
                await lib.MakeAssertionAsync(response,
                    options,
                    cpk.GetBytes(),
                    signCount - 1,
                    (_) => Task.FromResult(true));
            }
        }

        private static byte[] CreateAuthenticatorData(string relyingParty, ushort signCount, SHA256 sha, CredentialPublicKey cpk)
        {
            var attestedCredentialData = new AttestedCredentialData(_aaGuid, _credentialId, cpk);
            byte[] extensionsBytes = CBORObject.NewMap().Add("testing", true).EncodeToBytes();
            var extensions = new Extensions(extensionsBytes);
            byte[] rpId = Encoding.UTF8.GetBytes(relyingParty);
            byte[] rpIdHash = sha.ComputeHash(rpId);
            var flags = AuthenticatorFlags.AT | AuthenticatorFlags.ED | AuthenticatorFlags.UP | AuthenticatorFlags.UV;
            var authenticatorData = new AuthenticatorData(rpIdHash, flags, signCount, attestedCredentialData, extensions);
            return authenticatorData.ToByteArray();
        }

        private static void MakeEdDSA(out byte[] publicKey, out byte[] expandedPrivateKey)
        {
            var privateKeySeed = CreateRandomBytes(32);
            Ed25519.KeyPairFromSeed(out publicKey, out expandedPrivateKey, privateKeySeed);
        }

        private static byte[] SetEcDsaSigValue(byte[] sig)
        {
            int start = Array.FindIndex(sig, b => b != 0);

            if (start == sig.Length)
            {
                start--;
            }

            var length = sig.Length - start;
            byte[] dataBytes;

            var writeStart = 0;
            if ((sig[start] & (1 << 7)) != 0)
            {
                dataBytes = new byte[length + 1];
                writeStart = 1;
            }
            else
            {
                dataBytes = new byte[length];
            }
            Buffer.BlockCopy(sig, start, dataBytes, writeStart, length);
            return new byte[2]
            {
                0x02,
                BitConverter.GetBytes(dataBytes.Length)[0]
            }.Concat(dataBytes).ToArray();
        }

        private static byte[] EcDsaSigFromSig(byte[] sig, int keySize)
        {
            var coefficientSize = (int)Math.Ceiling((decimal)keySize / 8);
            IEnumerable<byte> R = sig.Take(coefficientSize);
            IEnumerable<byte> S = sig.TakeLast(coefficientSize);
            using (var ms = new MemoryStream())
            {
                using (var writer = new BinaryWriter(ms))
                {
                    writer.Write(new byte[1] { 0x30 });

                    var derR = SetEcDsaSigValue(R.ToArray());

                    var derS = SetEcDsaSigValue(S.ToArray());

                    var dataLen = derR.Length + derS.Length;

                    if (dataLen > 0x80)
                    {
                        writer.Write(new byte[1] { 0x81 });
                    }

                    writer.Write(new byte[1] { BitConverter.GetBytes(dataLen)[0] });

                    writer.Write(derR);

                    writer.Write(derS);
                }
                return ms.ToArray();
            }
        }
    }
}
