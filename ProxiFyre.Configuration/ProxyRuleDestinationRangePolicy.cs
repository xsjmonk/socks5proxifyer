using System.Collections.Generic;

namespace ProxiFyre.Configuration
{
    /// <summary>
    /// Copies configured destination ranges while preserving their configured values.
    /// </summary>
    internal static class ProxyRuleDestinationRangePolicy
    {
        public static List<string> Copy(IList<string> ipRanges)
        {
            if (ipRanges == null)
                return null;

            return new List<string>(ipRanges);
        }
    }
}
