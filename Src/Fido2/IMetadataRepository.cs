using System.Threading.Tasks;


namespace Fido2NetLib
{
    public interface IMetadataRepository
    {
        Task<MetadataTOCPayload> GetTocAsync();

        Task<MetadataStatement> GetMetadataStatementAsync(MetadataTOCPayloadEntry entry);
    }
}
