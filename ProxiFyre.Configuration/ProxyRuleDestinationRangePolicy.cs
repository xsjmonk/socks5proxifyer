using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace ProxiFyre.Configuration
{
    /// <summary>
    /// Copies configured destination ranges while preserving their configured values.
    /// </summary>
    internal static class ProxyRuleDestinationRangePolicy
    {
        public static bool IsValid(string cidr)
        {
            string reason;
            return TryValidate(cidr, out reason);
        }

        public static bool TryValidate(string cidr, out string reason)
        {
            reason = null;
            if (string.IsNullOrEmpty(cidr))
            {
                reason = "must be an IPv4 CIDR such as 192.168.100.0/24";
                return false;
            }

            var separator = cidr.IndexOf('/');
            if (separator <= 0 || separator != cidr.LastIndexOf('/') || separator == cidr.Length - 1)
            {
                reason = "must include an IPv4 address and prefix length";
                return false;
            }

            IPAddress address;
            if (!IPAddress.TryParse(cidr.Substring(0, separator), out address) ||
                address.AddressFamily != AddressFamily.InterNetwork)
            {
                reason = "must contain a valid IPv4 address";
                return false;
            }

            int prefixLength;
            if (!int.TryParse(
                    cidr.Substring(separator + 1),
                    NumberStyles.None,
                    CultureInfo.InvariantCulture,
                    out prefixLength) ||
                prefixLength < 0 ||
                prefixLength > 32)
            {
                reason = "must use an IPv4 prefix length from /0 through /32";
                return false;
            }

            return true;
        }

        public static List<string> Copy(IList<string> ipRanges)
        {
            if (ipRanges == null)
                return null;

            return new List<string>(ipRanges);
        }
    }
}
