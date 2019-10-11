using System;
using System.IO;
using System.Security.Cryptography;
using Fido2NetLib.Objects;
using Newtonsoft.Json;
using PeterO.Cbor;

namespace Fido2.Tests
{
    /// <summary>
    /// Base class used by all of the project's test classes.
    /// </summary>
    public class Fido2TestBase
    {
        /// <summary>
        /// A basic GUID that can be used as test data
        /// </summary>
        protected static readonly Guid _aaGuid = new Guid("F1D0F1D0-F1D0-F1D0-F1D0-F1D0F1D0F1D0");
        /// <summary>
        /// A basic credential ID that can be used as test data
        /// </summary>
        protected static readonly byte[] _credentialId = new byte[] { 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0 };

        protected Fido2TestBase()
        {

        }

        /// <summary>
        /// Reads a specified JSON file, and returns its deserialized contents.
        /// </summary>
        /// <typeparam name="T">The type of the object to deserialize</typeparam>
        /// <param name="fileName">The path to the JSON file ot deserialize</param>
        /// <returns></returns>
        protected static T ReadTestDataFromFile<T>(string fileName)
        {
            return JsonConvert.DeserializeObject<T>(File.ReadAllText(fileName));
        }

        /// <summary>
        /// Returns an instance of <see cref="ECDsaCng"/> that uses the specified COSE algorith and elliptic curve
        /// </summary>
        /// <param name="alg"></param>
        /// <param name="crv"></param>
        /// <returns></returns>
        protected static ECDsaCng MakeECDsa(COSE.Algorithm alg, COSE.EllipticCurve crv)
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

        /// <summary>
        /// Creates a new EC credential public key
        /// </summary>
        /// <param name="alg">Key algorithm</param>
        /// <param name="crv">Elliptic curve type</param>
        /// <param name="x">X coordinate</param>
        /// <param name="y">Y coordinate</param>
        /// <returns>A new credential public key</returns>
        protected static CredentialPublicKey MakeCredentialPublicKey(COSE.Algorithm alg, COSE.EllipticCurve crv, byte[] x, byte[] y)
        {
            return MakeCredentialPublicKey(COSE.KeyType.EC2, alg, crv, x, y, null, null);
        }

        /// <summary>
        /// Creates a new OKP credential public key
        /// </summary>
        /// <param name="alg">Key algorithm</param>
        /// <param name="crv">Elliptic curve type</param>
        /// <param name="x">X coordinate</param>
        /// <returns>A new credential public key</returns>
        protected static CredentialPublicKey MakeCredentialPublicKey(COSE.Algorithm alg, COSE.EllipticCurve crv, byte[] x)
        {
            return MakeCredentialPublicKey(COSE.KeyType.OKP, alg, crv, x, null, null, null);
        }

        /// <summary>
        /// Creates a new RSA credential public key
        /// </summary>
        /// <param name="alg">Key algorithm</param>
        /// <param name="n">Modulus</param>
        /// <param name="e">Exponent</param>
        /// <returns>A new credential public key</returns>
        protected static CredentialPublicKey MakeCredentialPublicKey(COSE.Algorithm alg, byte[] n, byte[] e)
        {
            return MakeCredentialPublicKey(COSE.KeyType.RSA, alg, null, null, null, n, e);
        }

        /// <summary>
        /// Creates a new credential public key using the specified characteristics
        /// </summary>
        /// <param name="kty">Key type</param>
        /// <param name="alg">Key algorithm</param>
        /// <param name="crv">Key elliptic curve</param>
        /// <param name="x">x coordinate</param>
        /// <param name="y">y coordinate</param>
        /// <param name="n">RSA modulus</param>
        /// <param name="e">RSA public exponent</param>
        /// <returns>A new credential public key</returns>
        protected static CredentialPublicKey MakeCredentialPublicKey(COSE.KeyType kty, COSE.Algorithm alg, COSE.EllipticCurve? crv, byte[] x, byte[] y, byte[] n, byte[] e)
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

        /// <summary>
        /// Creates a byte array of the specified size and fills it with random values
        /// </summary>
        /// <param name="size">Size of the array</param>
        /// <returns>A byte array with random values</returns>
        protected static byte[] CreateRandomBytes(int size)
        {
            using(var rng = RandomNumberGenerator.Create())
            {
                byte[] result = new byte[size];
                rng.GetBytes(result);
                return result;
            }
        }
    }
}
