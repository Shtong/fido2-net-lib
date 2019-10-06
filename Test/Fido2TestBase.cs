using System.IO;
using Newtonsoft.Json;

namespace Fido2.Tests
{
    /// <summary>
    /// Base class used by all of the project's test classes.
    /// </summary>
    public class Fido2TestBase
    {
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
    }
}
