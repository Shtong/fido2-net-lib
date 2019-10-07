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
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using PeterO.Cbor;
using Xunit;

namespace Fido2.Tests
{
    // todo: Create tests and name Facts and json files better.
    public class Fido2Tests
    {
        private readonly IMetadataService _metadataService;
        private readonly Fido2Configuration _config;

        public Fido2Tests()
        {
            var MDSAccessKey = Environment.GetEnvironmentVariable("fido2:MDSAccessKey");
            //var CacheDir = Environment.GetEnvironmentVariable("fido2:MDSCacheDirPath");

            var services = new ServiceCollection();

            var staticClient = new StaticMetadataRepository();

            var repos = new List<IMetadataRepository>();

            repos.Add(staticClient);

            if (!string.IsNullOrEmpty(MDSAccessKey))
            {
                repos.Add(new Fido2MetadataServiceRepository(MDSAccessKey, null));
            }

            services.AddDistributedMemoryCache();
            services.AddLogging();

            var provider = services.BuildServiceProvider();

            var memCache = provider.GetService<IDistributedCache>();

            var service = new DistributedCacheMetadataService(
                repos,
                memCache,
                provider.GetService<ILogger<DistributedCacheMetadataService>>());

            service.Initialize().Wait();

            _metadataService = service;

            _config = new Fido2Configuration { Origin = "https://localhost:44329" };
        }
        public static byte[] StringToByteArray(string hex)
        {
            hex = hex.Replace("-", "");
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        [Fact]
        public void TestAuthenticatorDataPa2rsing()
        {
            var bs = new byte[] { 1, 2, 3 };
            var x = CBORObject.NewMap().Add("bytes", bs);
            var s = x["bytes"].GetByteString();

            Assert.Equal(s, bs);
        }

        [Fact]
        public async Task TestPackedAttestationAsync()
        {
            var jsonPost = JsonConvert.DeserializeObject<AuthenticatorAttestationRawResponse>(File.ReadAllText("./attestationResultsPacked.json"));
            var o = AuthenticatorAttestationResponse.Parse(jsonPost);

            byte[] ad = o.AttestationObject.AuthData;

            var authData = new AuthenticatorData(ad);
            Assert.True(authData.ToByteArray().SequenceEqual(ad));

            var acdBytes = authData.AttestedCredentialData.ToByteArray();
            var acd = new AttestedCredentialData(acdBytes);
            Assert.True(acd.ToByteArray().SequenceEqual(acdBytes));
        }

        internal static byte[] SetEcDsaSigValue(byte[] sig)
        {
            var start = Array.FindIndex(sig, b => b != 0);

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
            return new byte[2] { 0x02, BitConverter.GetBytes(dataBytes.Length)[0] }.Concat(dataBytes).ToArray();
        }

        internal static byte[] EcDsaSigFromSig(byte[] sig, int keySize)
        {
            var coefficientSize = (int)Math.Ceiling((decimal)keySize / 8);
            var R = sig.Take(coefficientSize);
            var S = sig.TakeLast(coefficientSize);
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

        [Fact]
        public void TestAssertionResponse()
        {
            MakeAssertionResponse(COSE.KeyType.EC2, COSE.Algorithm.ES256);
            MakeAssertionResponse(COSE.KeyType.EC2, COSE.Algorithm.ES384, COSE.EllipticCurve.P384);
            MakeAssertionResponse(COSE.KeyType.EC2, COSE.Algorithm.ES512, COSE.EllipticCurve.P521);
            MakeAssertionResponse(COSE.KeyType.RSA, COSE.Algorithm.RS256);
            MakeAssertionResponse(COSE.KeyType.RSA, COSE.Algorithm.RS384);
            MakeAssertionResponse(COSE.KeyType.RSA, COSE.Algorithm.RS512);
            MakeAssertionResponse(COSE.KeyType.RSA, COSE.Algorithm.PS256);
            MakeAssertionResponse(COSE.KeyType.RSA, COSE.Algorithm.PS384);
            MakeAssertionResponse(COSE.KeyType.RSA, COSE.Algorithm.PS512);
            MakeAssertionResponse(COSE.KeyType.OKP, COSE.Algorithm.EdDSA, COSE.EllipticCurve.Ed25519);
        }

        internal async void MakeAssertionResponse(COSE.KeyType kty, COSE.Algorithm alg, COSE.EllipticCurve crv = COSE.EllipticCurve.P256)
        {
            const string rp = "fido2.azurewebsites.net";
            byte[] rpId = Encoding.UTF8.GetBytes(rp);
            var rpIdHash = SHA256.Create().ComputeHash(rpId);
            var flags = AuthenticatorFlags.AT | AuthenticatorFlags.ED | AuthenticatorFlags.UP | AuthenticatorFlags.UV;
            const ushort signCount = 0xf1d0;
            var aaguid = new Guid("F1D0F1D0-F1D0-F1D0-F1D0-F1D0F1D0F1D0");
            var credentialID = new byte[] { 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, };

            CredentialPublicKey cpk = null;
            ECDsaCng ecdsa = null;
            RSACng rsa = null;
            byte[] expandedPrivateKey = null;
            switch (kty)
            {
                case COSE.KeyType.EC2:
                    {
                        ecdsa = MakeECDsa(alg, crv);
                        var ecparams = ecdsa.ExportParameters(true);
                        cpk = MakeCredentialPublicKey(kty, alg, crv, ecparams.Q.X, ecparams.Q.Y);
                        break;
                    }
                case COSE.KeyType.RSA:
                    {
                        rsa = new RSACng();
                        var rsaparams = rsa.ExportParameters(true);
                        cpk = MakeCredentialPublicKey(kty, alg, rsaparams.Modulus, rsaparams.Exponent);
                        break;
                    }
                case COSE.KeyType.OKP:
                    {
                        MakeEdDSA(out var privateKeySeed, out var publicKey, out expandedPrivateKey);
                        cpk = MakeCredentialPublicKey(kty, alg, COSE.EllipticCurve.Ed25519, publicKey);
                        break;
                    }
                    throw new ArgumentOutOfRangeException(nameof(kty), $"Missing or unknown kty {kty}");
            }

            var acd = new AttestedCredentialData(aaguid, credentialID, cpk);
            var extBytes = CBORObject.NewMap().Add("testing", true).EncodeToBytes();
            var exts = new Extensions(extBytes);

            var ad = new AuthenticatorData(rpIdHash, flags, signCount, acd, exts);
            var authData = ad.ToByteArray();

            var challenge = new byte[128];
            var rng = RandomNumberGenerator.Create();
            rng.GetBytes(challenge);


            var clientData = new
            {
                Type = "webauthn.get",
                Challenge = challenge,
                Origin = rp,
            };
            var clientDataJson = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(clientData));

            var sha = SHA256.Create();
            var hashedClientDataJson = sha.ComputeHash(clientDataJson);
            byte[] data = new byte[authData.Length + hashedClientDataJson.Length];
            Buffer.BlockCopy(authData, 0, data, 0, authData.Length);
            Buffer.BlockCopy(hashedClientDataJson, 0, data, authData.Length, hashedClientDataJson.Length);
            byte[] signature = null;
            switch (kty)
            {
                case COSE.KeyType.EC2:
                    {
                        signature = ecdsa.SignData(data, CryptoUtils.algMap[(int)alg]);
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
                        signature = rsa.SignData(data, CryptoUtils.algMap[(int)alg], padding);
                        break;
                    }
                case COSE.KeyType.OKP:
                    {
                        signature = Ed25519.Sign(data, expandedPrivateKey);
                        break;
                    }

                default:
                    throw new ArgumentOutOfRangeException(nameof(kty), $"Missing or unknown kty {kty}");
            }

            if (kty == COSE.KeyType.EC2)
            {
                signature = EcDsaSigFromSig(signature, ecdsa.KeySize);
            }

            var userHandle = new byte[16];
            rng.GetBytes(userHandle);

            var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
            {
                AuthenticatorData = authData,
                Signature = signature,
                ClientDataJson = clientDataJson,
                UserHandle = userHandle,
            };

            var lib = new Fido2NetLib.Fido2(new Fido2Configuration()
            {
                ServerDomain = rp,
                ServerName = rp,
                Origin = rp,
            });
            var existingCredentials = new List<PublicKeyCredentialDescriptor>();
            var cred = new PublicKeyCredentialDescriptor
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 }
            };
            existingCredentials.Add(cred);

            var options = lib.GetAssertionOptions(existingCredentials, null, null);
            options.Challenge = challenge;
            var response = new AuthenticatorAssertionRawResponse()
            {
                Response = assertion,
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
            };
            IsUserHandleOwnerOfCredentialIdAsync callback = (args) =>
            {
                return Task.FromResult(true);
            };

            // This should not throw an exception
            await lib.MakeAssertionAsync(response, options, cpk.GetBytes(), signCount - 1, callback);
        }

        internal void MakeEdDSA(out byte[] privateKeySeed, out byte[] publicKey, out byte[] expandedPrivateKey)
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                privateKeySeed = new byte[32];
                rng.GetBytes(privateKeySeed);
                publicKey = new byte[32];
                expandedPrivateKey = new byte[64];
                Ed25519.KeyPairFromSeed(out publicKey, out expandedPrivateKey, privateKeySeed);
            }
        }

        internal ECDsaCng MakeECDsa(COSE.Algorithm alg, COSE.EllipticCurve crv)
        {
            ECCurve curve;
            switch (alg)
            {
                case COSE.Algorithm.ES256:
                    switch (crv)
                    {
                        case COSE.EllipticCurve.P256:
                        case COSE.EllipticCurve.P256K:
                            curve = ECCurve.NamedCurves.nistP256;
                            break;
                        default:
                            throw new ArgumentOutOfRangeException(nameof(crv), $"Missing or unknown crv {crv}");
                    }
                    break;
                case COSE.Algorithm.ES384:
                    switch (crv) // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
                    {
                        case COSE.EllipticCurve.P384:
                            curve = ECCurve.NamedCurves.nistP384;
                            break;
                        default:
                            throw new ArgumentOutOfRangeException(nameof(crv), $"Missing or unknown crv {crv}");
                    }
                    break;
                case COSE.Algorithm.ES512:
                    switch (crv) // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
                    {
                        case COSE.EllipticCurve.P521:
                            curve = ECCurve.NamedCurves.nistP521;
                            break;
                        default:
                            throw new ArgumentOutOfRangeException(nameof(crv), $"Missing or unknown crv {crv}");
                    }
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(alg), $"Missing or unknown alg {alg}");
            }
            return new ECDsaCng(curve);
        }

        internal CredentialPublicKey MakeCredentialPublicKey(COSE.KeyType kty, COSE.Algorithm alg, COSE.EllipticCurve crv, byte[] x, byte[] y)
        {
            return MakeCredentialPublicKey(kty, alg, crv, x, y, null, null);
        }

        internal CredentialPublicKey MakeCredentialPublicKey(COSE.KeyType kty, COSE.Algorithm alg, COSE.EllipticCurve crv, byte[] x)
        {
            return MakeCredentialPublicKey(kty, alg, crv, x, null, null, null);
        }

        internal CredentialPublicKey MakeCredentialPublicKey(COSE.KeyType kty, COSE.Algorithm alg, byte[] n, byte[] e)
        {
            return MakeCredentialPublicKey(kty, alg, null, null, null, n, e);
        }

        internal CredentialPublicKey MakeCredentialPublicKey(COSE.KeyType kty, COSE.Algorithm alg, COSE.EllipticCurve? crv, byte[] x, byte[] y, byte[] n, byte[] e)
        {
            var cpk = CBORObject.NewMap();
            cpk.Add(COSE.KeyCommonParameter.KeyType, kty);
            cpk.Add(COSE.KeyCommonParameter.Alg, alg);
            switch (kty)
            {
                case COSE.KeyType.EC2:
                    cpk.Add(COSE.KeyTypeParameter.X, x);
                    cpk.Add(COSE.KeyTypeParameter.Y, y);
                    cpk.Add(COSE.KeyTypeParameter.Crv, crv);
                    break;
                case COSE.KeyType.RSA:
                    cpk.Add(COSE.KeyTypeParameter.N, n);
                    cpk.Add(COSE.KeyTypeParameter.E, e);
                    break;
                case COSE.KeyType.OKP:
                    cpk.Add(COSE.KeyTypeParameter.X, x);
                    cpk.Add(COSE.KeyTypeParameter.Crv, crv);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(kty), kty, "Invalid COSE key type");
            }
            return new CredentialPublicKey(cpk);
        }
    }
}
