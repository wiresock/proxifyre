using ProxiFyre.Configuration;
using System;

namespace ProxiFyreUI.Infrastructure
{
    /// <summary>
    /// Keeps persisted unsafe TLS choices from becoming implicitly confirmed when a rule
    /// changes from a non-TLS transport to TLS.
    /// </summary>
    public static class InvalidCertificateConfirmationPolicy
    {
        public static bool IsPersistedSelectionConfirmed(string transport, bool allowInvalidCertificate)
        {
            if (!allowInvalidCertificate)
                return false;

            string canonicalTransport;
            return ConfigurationNormalizer.TryGetCanonicalTransport(transport, out canonicalTransport) &&
                   string.Equals(canonicalTransport, "TLS", StringComparison.Ordinal);
        }

        public static bool RequiresConfirmation(bool tlsSelected, bool allowInvalidCertificate,
            bool alreadyConfirmed)
        {
            return tlsSelected && allowInvalidCertificate && !alreadyConfirmed;
        }
    }
}
