using System;
using System.Collections.Generic;
using System.Text;
using Fido2NetLib;
using Shouldly;
using Xunit;

namespace Fido2
{
    public class Base64UrlTests
    {
        [Theory]
        [MemberData(nameof(GetData))]
        public void EncodeAndDecodeResultsAreEqual(byte[] data)
        {
            // Act
            var encodedBytes = Base64Url.Encode(data);
            var decodedBytes = Base64Url.Decode(encodedBytes);

            // Assert
            decodedBytes.ShouldBe(data);
        }

        [Fact]
        public void EncodeThrowsOnNull()
        {
            Should.Throw<ArgumentNullException>(() =>
            {
                Base64Url.Encode(null);
            });
        }

        [Fact]
        public void DecodeThrowsOnNull()
        {
            Should.Throw<ArgumentNullException>(() =>
            {
                Base64Url.Decode(null);
            });
        }

        public static IEnumerable<object[]> GetData()
        {
            yield return new[] { Encoding.UTF8.GetBytes("This is a string fragment to test Base64Url encoding & decoding.") };
            yield return new[] { Array.Empty<byte>() };
        }
    }
}
