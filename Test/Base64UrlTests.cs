using System;
using System.Collections.Generic;
using System.Text;
using Fido2NetLib;
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
            Assert.Equal(data, decodedBytes);
        }           

        [Fact]
        public void EncodeThrowsOnNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                var encodedBytes = Base64Url.Encode(null);
            });
        }

        [Fact]
        public void DecodeThrowsOnNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                var encodedBytes = Base64Url.Decode(null);
            });
        }

        public static IEnumerable<object[]> GetData()
        {
            return new TestDataGenerator();
        }


        private class TestDataGenerator : TheoryData<byte[]>
        {
            public TestDataGenerator()
            {
                Add(Encoding.UTF8.GetBytes("This is a string fragment to test Base64Url encoding & decoding."));
                Add(Array.Empty<byte>());
            }
        }
    }
}
