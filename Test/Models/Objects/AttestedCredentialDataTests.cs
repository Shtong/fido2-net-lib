using System;
using System.Security.Cryptography;
using Chaos.NaCl;
using Fido2NetLib.Objects;
using PeterO.Cbor;
using Shouldly;
using Xunit;

namespace Fido2.Tests.Models.Objects
{
    public class AttestedCredentialDataTests : Fido2TestBase
    {
        private static readonly Guid _aaGuid = new Guid("F1D0F1D0-F1D0-F1D0-F1D0-F1D0F1D0F1D0");
        private static readonly byte[] _credentialId = new byte[] { 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0 };

        [Fact]
        public void GeneratesCorrectDataWithES256()
        {
            using (ECDsaCng ecdsa = MakeECDsa(COSE.Algorithm.ES256, COSE.EllipticCurve.P256))
            {
                ECParameters ecparams = ecdsa.ExportParameters(true);
                CredentialPublicKey cpk = MakeCredentialPublicKey(
                    COSE.KeyType.EC2,
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
                    COSE.KeyType.RSA,
                    COSE.Algorithm.RS256,
                    rsaparams.Modulus,
                    rsaparams.Exponent);

                VerifyCredentialData(cpk);
            }
        }

        [Fact]
        public void GeneratesCorrectDataWithOKP()
        {
            MakeEdDSA(out _, out var publicKey, out _);
            CredentialPublicKey cpk = MakeCredentialPublicKey(
                COSE.KeyType.OKP,
                COSE.Algorithm.EdDSA,
                COSE.EllipticCurve.Ed25519,
                publicKey);

            VerifyCredentialData(cpk);
        }

        private void VerifyCredentialData(CredentialPublicKey credentialPublicKey)
        {
            var acdFromConst = new AttestedCredentialData(_aaGuid, _credentialId, credentialPublicKey);
            var acdBytes = acdFromConst.ToByteArray();
            var acdFromBytes = new AttestedCredentialData(acdBytes);

            acdFromBytes.ToByteArray().ShouldBe(acdFromConst.ToByteArray());
        }

        private ECDsaCng MakeECDsa(COSE.Algorithm alg, COSE.EllipticCurve crv)
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

        private CredentialPublicKey MakeCredentialPublicKey(
            COSE.KeyType kty,
            COSE.Algorithm alg,
            COSE.EllipticCurve crv,
            byte[] x,
            byte[] y)
        {
            return MakeCredentialPublicKey(kty, alg, crv, x, y, null, null);
        }

        private CredentialPublicKey MakeCredentialPublicKey(
            COSE.KeyType kty,
            COSE.Algorithm alg,
            COSE.EllipticCurve crv,
            byte[] x)
        {
            return MakeCredentialPublicKey(kty, alg, crv, x, null, null, null);
        }

        private CredentialPublicKey MakeCredentialPublicKey(
            COSE.KeyType kty,
            COSE.Algorithm alg,
            byte[] n,
            byte[] e)
        {
            return MakeCredentialPublicKey(kty, alg, null, null, null, n, e);
        }

        private CredentialPublicKey MakeCredentialPublicKey(COSE.KeyType kty, COSE.Algorithm alg, COSE.EllipticCurve? crv, byte[] x, byte[] y, byte[] n, byte[] e)
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

        private void MakeEdDSA(out byte[] privateKeySeed, out byte[] publicKey, out byte[] expandedPrivateKey)
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
    }
}
