using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Fido2NetLib;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Fido2.Tests
{
    public class AuthenticatorAttestationResponseTests : Fido2TestBase
    {
        private readonly Fido2Configuration _config = new Fido2Configuration
        {
            Origin = "https://localhost:44329"
        };

        private readonly IMetadataService _metadataService = CreateTestMds();

        /// <summary>
        /// Creates the instance of <see cref="IMetadataService"/> used during tests
        /// </summary>
        /// <returns></returns>
        private static IMetadataService CreateTestMds()
        {
            var mdsAccessKey = Environment.GetEnvironmentVariable("fido2:MDSAccessKey");

            var repos = new List<IMetadataRepository>
            {
                new StaticMetadataRepository()
            };

            if (!string.IsNullOrEmpty(mdsAccessKey))
            {
                repos.Add(new Fido2MetadataServiceRepository(mdsAccessKey, null));
            }

            var services = new ServiceCollection();
            services.AddDistributedMemoryCache();
            services.AddLogging();
            var serviceProvider = services.BuildServiceProvider();

            var result = new DistributedCacheMetadataService(
                repos,
                serviceProvider.GetService<IDistributedCache>(),
                serviceProvider.GetService<ILogger<DistributedCacheMetadataService>>());

            result.Initialize().Wait(); // TODO : Is there a better approach that calling Wait?

            return result;
        }

        [Fact]
        public async Task VerifyBasic()
        {
            var options = ReadTestDataFromFile<CredentialCreateOptions>("./options1.json");
            var response = ReadTestDataFromFile<AuthenticatorAttestationRawResponse>("./json1.json");
            var o = AuthenticatorAttestationResponse.Parse(response);

            // This should not throw an exception
            await o.VerifyAsync(options, _config, (x) => Task.FromResult(true), _metadataService, null);
        }

        [Fact]
        public async Task VerifyAttestationNone()
        {
            var options = ReadTestDataFromFile<CredentialCreateOptions>("./AttestationNoneOptions.json");
            var response = ReadTestDataFromFile<AuthenticatorAttestationRawResponse>("./AttestationNoneResponse.json");
            var o = AuthenticatorAttestationResponse.Parse(response);

            // This should not throw an exception
            await o.VerifyAsync(options, _config, (x) => Task.FromResult(true), _metadataService, null);
        }
    }
}
