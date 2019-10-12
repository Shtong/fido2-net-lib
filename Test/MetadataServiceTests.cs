using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Fido2NetLib;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Shouldly;
using Xunit;

namespace Fido2
{
    public class MetadataServiceTests
    {

        [Fact]
        public async Task ConformanceTestClient()
        {
            var client = new ConformanceMetadataRepository(null, "http://localhost");
            MetadataTOCPayload toc = await client.GetToc();

            MetadataStatement statement = await client.GetMetadataStatement(toc.Entries[toc.Entries.Length - 1]);

            toc.Entries.Length.ShouldBeGreaterThan(0);
            statement.Description.ShouldNotBeNull();
        }

        [Fact]
        public async Task DistributedCacheMetadataService_Works()
        {
            var clients = new List<IMetadataRepository>
            {
                new StaticMetadataRepository(DateTime.UtcNow.AddDays(5)),
            };

            var services = new ServiceCollection();
            services.AddDistributedMemoryCache();
            services.AddLogging();
            ServiceProvider provider = services.BuildServiceProvider();

            IDistributedCache memCache = provider.GetService<IDistributedCache>();

            var service = new DistributedCacheMetadataService(
                clients,
                memCache,
                provider.GetService<ILogger<DistributedCacheMetadataService>>());

            await service.Initialize();

            MetadataTOCPayloadEntry entry = service.GetEntry(Guid.Parse("6d44ba9b-f6ec-2e49-b930-0c8fe920cb73"));
            var cacheEntry = await memCache.GetStringAsync("DistributedCacheMetadataService:StaticMetadataRepository:Entry:6d44ba9b-f6ec-2e49-b930-0c8fe920cb73");

            entry.MetadataStatement.Description.ShouldBe("Yubico Security Key NFC");
            cacheEntry.ShouldNotBeNull();
        }

        [Fact]
        public async Task DistributedCacheMetadataService_CacheSuppressionWorks()
        {
            var clients = new List<IMetadataRepository>
            {
                new StaticMetadataRepository(null),
            };

            var services = new ServiceCollection();
            services.AddDistributedMemoryCache();
            services.AddLogging();
            ServiceProvider provider = services.BuildServiceProvider();

            IDistributedCache memCache = provider.GetService<IDistributedCache>();

            var service = new DistributedCacheMetadataService(
                clients,
                memCache,
                provider.GetService<ILogger<DistributedCacheMetadataService>>());

            await service.Initialize();

            MetadataTOCPayloadEntry entry = service.GetEntry(Guid.Parse("6d44ba9b-f6ec-2e49-b930-0c8fe920cb73"));
            var cacheEntry = await memCache.GetStringAsync("DistributedCacheMetadataService:StaticMetadataRepository:Entry:6d44ba9b-f6ec-2e49-b930-0c8fe920cb73");

            entry.MetadataStatement.Description.ShouldBe("Yubico Security Key NFC");
            cacheEntry.ShouldBeNull();
        }
    }
}
