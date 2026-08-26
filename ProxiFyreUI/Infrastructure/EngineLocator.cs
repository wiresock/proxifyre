using Microsoft.Win32;
using ProxiFyre.Configuration;
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ProxiFyreUI.Infrastructure
{
    public enum EngineLocationSource
    {
        None,
        ServiceRegistration,
        BesideUserInterface,
        UserSelection
    }

    public sealed class EngineLocation
    {
        public EngineLocation(string path, EngineLocationSource source, string error = null)
        {
            Path = path;
            Source = source;
            Error = error;
        }

        public string Path { get; }
        public EngineLocationSource Source { get; }
        public string Error { get; }
        public bool IsResolved => string.IsNullOrWhiteSpace(Error) &&
                                  !string.IsNullOrWhiteSpace(Path) && File.Exists(Path);
        public string ConfigurationPath => IsResolved ? ProxiFyrePaths.GetConfigurationPath(Path) : null;
        public string LogDirectoryPath => IsResolved ? ProxiFyrePaths.GetLogDirectoryPath(Path) : null;
    }

    public interface IEngineLocator
    {
        EngineLocation Resolve(UiSettings settings);
        EngineLocation ResolveTrustedUninstallFallback(UiSettings settings, string currentEnginePath);
        EngineLocation ValidateUserSelection(string path);
        string GetRegisteredServiceImagePath();
        bool IsRegisteredServiceExecutable(string expectedPath);
    }

    public sealed class EngineLocator : IEngineLocator
    {
        private const string ServiceRegistryPath = @"SYSTEM\CurrentControlSet\Services\" +
                                                   ProxiFyrePaths.ServiceName;
        private readonly Func<string> _registeredServiceImagePathReader;
        private readonly Func<string, bool> _engineValidator;
        private readonly string _userInterfaceExecutablePath;

        public EngineLocator()
            : this(ReadRegisteredServiceImagePath, EngineExecutableValidator.IsTrusted,
                Assembly.GetExecutingAssembly().Location)
        {
        }

        /// <summary>
        /// Test seam for the SCM registry value, elevated-engine identity check, and UI path.
        /// Production callers should use the parameterless constructor.
        /// </summary>
        public EngineLocator(Func<string> registeredServiceImagePathReader,
            Func<string, bool> engineValidator, string userInterfaceExecutablePath)
        {
            _registeredServiceImagePathReader = registeredServiceImagePathReader ??
                                                throw new ArgumentNullException(nameof(registeredServiceImagePathReader));
            _engineValidator = engineValidator ?? throw new ArgumentNullException(nameof(engineValidator));
            _userInterfaceExecutablePath = userInterfaceExecutablePath;
        }

        public EngineLocation Resolve(UiSettings settings)
        {
            string registered;
            try
            {
                registered = GetRegisteredServiceImagePath();
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException || ex is IOException ||
                                       ex is InvalidDataException ||
                                       ex is System.Security.SecurityException)
            {
                return new EngineLocation(null, EngineLocationSource.ServiceRegistration,
                    "The installed service registration could not be read. " + ex.Message);
            }
            if (!string.IsNullOrWhiteSpace(registered))
            {
                string executable;
                if (!ServiceImagePathParser.TryGetExecutablePath(registered, out executable))
                    return new EngineLocation(null, EngineLocationSource.ServiceRegistration,
                        "The installed service registration contains an invalid executable path.");

                executable = Environment.ExpandEnvironmentVariables(executable);
                if (_engineValidator(executable))
                    return new EngineLocation(Path.GetFullPath(executable), EngineLocationSource.ServiceRegistration);

                return new EngineLocation(executable, EngineLocationSource.ServiceRegistration,
                    "The installed service executable could not be found or does not have a trusted ProxiFyre identity.");
            }

            var userInterfaceDirectory = string.IsNullOrWhiteSpace(_userInterfaceExecutablePath)
                ? null
                : Path.GetDirectoryName(Path.GetFullPath(_userInterfaceExecutablePath));
            if (!string.IsNullOrWhiteSpace(userInterfaceDirectory))
            {
                var adjacent = Path.Combine(userInterfaceDirectory, ProxiFyrePaths.EngineExecutableName);
                if (_engineValidator(adjacent))
                    return new EngineLocation(Path.GetFullPath(adjacent), EngineLocationSource.BesideUserInterface);
            }

            if (settings != null && !string.IsNullOrWhiteSpace(settings.SelectedEnginePath))
            {
                var selection = ValidateUserSelection(settings.SelectedEnginePath);
                if (selection.IsResolved)
                    return selection;
            }

            return new EngineLocation(null, EngineLocationSource.None,
                "ProxiFyre.exe was not found. Select the engine executable to continue.");
        }

        public EngineLocation ValidateUserSelection(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return new EngineLocation(null, EngineLocationSource.None, "No engine executable was selected.");

            string fullPath;
            try { fullPath = Path.GetFullPath(path); }
            catch (Exception ex) when (ex is ArgumentException || ex is NotSupportedException || ex is PathTooLongException)
            {
                return new EngineLocation(path, EngineLocationSource.UserSelection, "The selected path is invalid.");
            }

            if (!_engineValidator(fullPath))
                return new EngineLocation(fullPath, EngineLocationSource.UserSelection,
                    "Select an existing ProxiFyre.exe with a valid ProxiFyre engine identity.");

            return new EngineLocation(fullPath, EngineLocationSource.UserSelection);
        }

        /// <summary>
        /// Finds a trusted executable that can host the fixed service-uninstall command when
        /// the registered executable itself is missing or invalid. This deliberately does not
        /// participate in normal engine resolution, which remains fail-closed on a broken
        /// installed-service registration.
        /// </summary>
        public EngineLocation ResolveTrustedUninstallFallback(UiSettings settings,
            string currentEnginePath)
        {
            var candidates = new[]
            {
                new { Path = currentEnginePath, Source = EngineLocationSource.UserSelection },
                new { Path = GetAdjacentEnginePath(), Source = EngineLocationSource.BesideUserInterface },
                new
                {
                    Path = settings?.SelectedEnginePath,
                    Source = EngineLocationSource.UserSelection
                }
            };
            var seen = new System.Collections.Generic.HashSet<string>(
                StringComparer.OrdinalIgnoreCase);
            foreach (var candidate in candidates)
            {
                if (string.IsNullOrWhiteSpace(candidate.Path))
                    continue;

                var validated = ValidateUserSelection(candidate.Path);
                if (!validated.IsResolved || !seen.Add(validated.Path))
                    continue;
                return new EngineLocation(validated.Path, candidate.Source);
            }

            return new EngineLocation(null, EngineLocationSource.None,
                "No trusted ProxiFyre.exe is available to run the service uninstall command.");
        }

        public string GetRegisteredServiceImagePath()
        {
            return _registeredServiceImagePathReader();
        }

        public bool IsRegisteredServiceExecutable(string expectedPath)
        {
            if (string.IsNullOrWhiteSpace(expectedPath))
                return false;

            string registeredExecutable;
            if (!ServiceImagePathParser.TryGetExecutablePath(
                    GetRegisteredServiceImagePath(), out registeredExecutable))
                return false;

            string expectedFullPath;
            try
            {
                expectedFullPath = Path.GetFullPath(expectedPath);
            }
            catch (Exception ex) when (ex is ArgumentException || ex is NotSupportedException ||
                                       ex is PathTooLongException)
            {
                return false;
            }

            return string.Equals(registeredExecutable, expectedFullPath,
                       StringComparison.OrdinalIgnoreCase) &&
                   _engineValidator(registeredExecutable);
        }

        private string GetAdjacentEnginePath()
        {
            if (string.IsNullOrWhiteSpace(_userInterfaceExecutablePath))
                return null;
            try
            {
                var directory = Path.GetDirectoryName(Path.GetFullPath(_userInterfaceExecutablePath));
                return string.IsNullOrWhiteSpace(directory)
                    ? null
                    : Path.Combine(directory, ProxiFyrePaths.EngineExecutableName);
            }
            catch (Exception ex) when (ex is ArgumentException || ex is NotSupportedException ||
                                       ex is PathTooLongException)
            {
                return null;
            }
        }

        private static string ReadRegisteredServiceImagePath()
        {
            using (var key = Registry.LocalMachine.OpenSubKey(ServiceRegistryPath, false))
            {
                if (key == null)
                    return null;
                return RequireValidServiceImagePathValue(key.GetValue("ImagePath", null,
                    RegistryValueOptions.DoNotExpandEnvironmentNames));
            }
        }

        internal static string RequireValidServiceImagePathValue(object value)
        {
            var imagePath = value as string;
            if (string.IsNullOrWhiteSpace(imagePath))
                throw new InvalidDataException(
                    "The installed service registration has no valid ImagePath value.");
            return imagePath;
        }

    }

    internal static class EngineExecutableValidator
    {
        internal const string EngineConfigurationSha256 =
            "FEB7B159597D51A915D659A56599AA74D8B2104056B9E77F7FD9E1992600EEB4";
        internal const string LoggingConfigurationSha256 =
            "BB92B3CF996D7DBCF1B94B34228F80478DD569E2CC84D44BDD994D08018917DC";
        private static readonly string[] SignedDependencyFileNames =
        {
            "ProxiFyre.Configuration.dll",
            "socksify.dll",
            "Newtonsoft.Json.dll",
            "NLog.dll",
            "Topshelf.dll"
        };

        public static bool IsTrusted(string path)
        {
            string[] payloadPaths;
            try
            {
                payloadPaths = GetLifecyclePayloadPaths(path);
            }
            catch (Exception ex) when (ex is ArgumentException || ex is NotSupportedException ||
                                       ex is PathTooLongException)
            {
                return false;
            }

            foreach (var payloadPath in payloadPaths)
            {
                if (!IsTrustedPayloadFile(payloadPath))
                    return false;
            }
            return true;
        }

        internal static string[] GetLifecyclePayloadPaths(string enginePath)
        {
            var fullEnginePath = Path.GetFullPath(enginePath);
            var directory = Path.GetDirectoryName(fullEnginePath);
            if (string.IsNullOrWhiteSpace(directory))
                throw new ArgumentException("The engine executable must have a directory.",
                    nameof(enginePath));

            var payload = new string[SignedDependencyFileNames.Length + 3];
            payload[0] = fullEnginePath;
            for (var index = 0; index < SignedDependencyFileNames.Length; index++)
                payload[index + 1] = Path.Combine(directory, SignedDependencyFileNames[index]);
            payload[payload.Length - 2] = fullEnginePath + ".config";
            payload[payload.Length - 1] = Path.Combine(directory, "NLog.config");
            return payload;
        }

        internal static bool IsTrustedPayloadFile(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return false;
            var fileName = Path.GetFileName(path);
            if (string.Equals(fileName, ProxiFyrePaths.EngineExecutableName,
                    StringComparison.OrdinalIgnoreCase))
                return IsTrustedEngineExecutable(path);
            foreach (var dependencyFileName in SignedDependencyFileNames)
            {
                if (string.Equals(fileName, dependencyFileName,
                        StringComparison.OrdinalIgnoreCase))
                {
#if DEBUG
                    return true;
#else
                    return AuthenticodeExecutableValidator.IsSignedByExpectedPublisher(path);
#endif
                }
            }

            if (string.Equals(fileName, "ProxiFyre.exe.config",
                    StringComparison.OrdinalIgnoreCase))
            {
#if DEBUG
                return true;
#else
                return PayloadHashValidator.HasExpectedSha256(path, EngineConfigurationSha256);
#endif
            }
            if (string.Equals(fileName, "NLog.config", StringComparison.OrdinalIgnoreCase))
            {
#if DEBUG
                return true;
#else
                return PayloadHashValidator.HasExpectedSha256(path, LoggingConfigurationSha256);
#endif
            }
            return false;
        }

        private static bool IsTrustedEngineExecutable(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path) ||
                !string.Equals(Path.GetFileName(path), ProxiFyrePaths.EngineExecutableName,
                    StringComparison.OrdinalIgnoreCase))
                return false;

            try
            {
                var info = FileVersionInfo.GetVersionInfo(path);
                // A matching basename alone is not an adequate execution boundary: lifecycle
                // commands run elevated. Require the version resource emitted by the engine
                // project as a second identity check before launching install/uninstall.
                if (!string.Equals(info.OriginalFilename, ProxiFyrePaths.EngineExecutableName,
                        StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(info.ProductName, "ProxiFyre", StringComparison.Ordinal))
                    return false;
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException ||
                                       ex is ArgumentException)
            {
                return false;
            }

#if DEBUG
            // Local development binaries are unsigned until the release repack/sign pipeline.
            // Production builds below require the expected Authenticode publisher.
            return true;
#else
            return AuthenticodeExecutableValidator.IsSignedByExpectedPublisher(path);
#endif
        }
    }

    internal static class AuthenticodeExecutableValidator
    {
        private const string ExpectedPublisher = "The Anti-Cloud Corporation";
        // SHA-256 of the encoded public-key bytes returned by X509Certificate2.GetPublicKey()
        // for the certificate used to sign the v2.4.0 production release. Pinning the key keeps
        // a same-name certificate rooted in the current user's trust store from being accepted.
        private const string ExpectedPublicKeySha256 =
            "07D12F0ABEA80E9A9A71899B68E1B6CB940E58B2CAF37874CD0A62EB2E2E4C5A";
        private const uint TrustUiNone = 2;
        private const uint RevokeNone = 0;
        private const uint ChoiceFile = 1;
        private const uint StateActionVerify = 1;
        private const uint StateActionClose = 2;
        private const uint CacheOnlyUrlRetrieval = 0x00001000;
        private const uint VerifySpecificSignature = 0x00000001;
        private const uint GetSecondarySignatureCount = 0x00000002;
        private const uint MaximumSecondarySignatures = 16;
        private const uint LoadWithAlteredSearchPath = 0x00000008;
        private const uint LoadLibrarySearchSystem32 = 0x00000800;
        private const int ErrorInvalidParameter = 87;
        private static readonly Guid VerifyAction =
            new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        private static readonly Lazy<WinTrustApi> NativeApi =
            new Lazy<WinTrustApi>(WinTrustApi.Load);

        public static bool IsSignedByExpectedPublisher(string path)
        {
            try
            {
                if (RequiresLegacyWinTrust(Environment.OSVersion.Version))
                {
                    using (var certificate = GetLegacyVerifiedSignerCertificate(path))
                        return IsExpectedSigner(certificate);
                }

                uint secondarySignatureCount;
                using (var certificate = GetVerifiedSignerCertificate(path, 0, true,
                           out secondarySignatureCount))
                {
                    if (IsExpectedSigner(certificate))
                        return true;
                }

                // A corrupt count must fail closed without permitting an unbounded verification
                // loop over attacker-controlled signature metadata.
                if (secondarySignatureCount > MaximumSecondarySignatures)
                    return false;
                for (uint signatureIndex = 1;
                     signatureIndex <= secondarySignatureCount; signatureIndex++)
                {
                    uint ignoredCount;
                    using (var certificate = GetVerifiedSignerCertificate(path,
                               signatureIndex, false, out ignoredCount))
                    {
                        if (IsExpectedSigner(certificate))
                            return true;
                    }
                }
                return false;
            }
            catch (Exception ex) when (ex is CryptographicException || ex is IOException ||
                                       ex is UnauthorizedAccessException || ex is ArgumentException)
            {
                return false;
            }
        }

        internal static bool RequiresLegacyWinTrust(Version operatingSystemVersion)
        {
            return operatingSystemVersion != null &&
                   operatingSystemVersion < new Version(6, 2);
        }

        private static bool IsExpectedSigner(X509Certificate2 certificate)
        {
            if (certificate == null || !string.Equals(
                    certificate.GetNameInfo(X509NameType.SimpleName, false),
                    ExpectedPublisher, StringComparison.Ordinal))
                return false;

            using (var sha256 = SHA256.Create())
            {
                var publicKeyHash = BitConverter.ToString(
                    sha256.ComputeHash(certificate.GetPublicKey())).Replace("-", string.Empty);
                return string.Equals(publicKeyHash, ExpectedPublicKeySha256,
                    StringComparison.OrdinalIgnoreCase);
            }
        }

        private static X509Certificate2 GetVerifiedSignerCertificate(string path,
            uint signatureIndex, bool getSecondarySignatureCount,
            out uint secondarySignatureCount)
        {
            secondarySignatureCount = 0;
            WinTrustApi nativeApi;
            if (!TryGetNativeApi(out nativeApi))
                return null;

            IntPtr pathPointer = IntPtr.Zero;
            IntPtr fileInfoPointer = IntPtr.Zero;
            IntPtr signatureSettingsPointer = IntPtr.Zero;
            IntPtr trustDataPointer = IntPtr.Zero;
            try
            {
                pathPointer = Marshal.StringToCoTaskMemUni(path);
                var fileInfo = new WinTrustFileInfo
                {
                    StructSize = (uint)Marshal.SizeOf(typeof(WinTrustFileInfo)),
                    FilePath = pathPointer
                };
                fileInfoPointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WinTrustFileInfo)));
                Marshal.StructureToPtr(fileInfo, fileInfoPointer, false);

                // Verify one explicit signature index. This prevents WinTrust from accepting a
                // different embedded signature than the signer certificate pinned below.
                var signatureSettings = new WinTrustSignatureSettings
                {
                    StructSize = (uint)Marshal.SizeOf(typeof(WinTrustSignatureSettings)),
                    Flags = VerifySpecificSignature |
                            (getSecondarySignatureCount ? GetSecondarySignatureCount : 0),
                    Index = signatureIndex
                };
                signatureSettingsPointer = Marshal.AllocHGlobal(
                    Marshal.SizeOf(typeof(WinTrustSignatureSettings)));
                Marshal.StructureToPtr(signatureSettings, signatureSettingsPointer, false);

                var trustData = new WinTrustData
                {
                    StructSize = (uint)Marshal.SizeOf(typeof(WinTrustData)),
                    UiChoice = TrustUiNone,
                    RevocationChecks = RevokeNone,
                    UnionChoice = ChoiceFile,
                    FileInfo = fileInfoPointer,
                    StateAction = StateActionVerify,
                    ProviderFlags = CacheOnlyUrlRetrieval,
                    SignatureSettings = signatureSettingsPointer
                };
                trustDataPointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WinTrustData)));
                Marshal.StructureToPtr(trustData, trustDataPointer, false);

                var action = VerifyAction;
                var verificationResult = nativeApi.VerifyTrust(new IntPtr(-1), ref action,
                    trustDataPointer);
                signatureSettings = (WinTrustSignatureSettings)Marshal.PtrToStructure(
                    signatureSettingsPointer, typeof(WinTrustSignatureSettings));
                if (getSecondarySignatureCount)
                    secondarySignatureCount = signatureSettings.SecondarySignatureCount;
                if (verificationResult != 0 ||
                    signatureSettings.VerifiedSignatureIndex != signatureIndex)
                    return null;

                // Bind the publisher/key check to the certificate in the exact provider state
                // produced by the successful verification above. CreateFromSignedFile is not
                // sufficient here because it can return a different signer for multi-signed PEs.
                trustData = (WinTrustData)Marshal.PtrToStructure(
                    trustDataPointer, typeof(WinTrustData));
                return GetSignerCertificateFromState(nativeApi, trustData.StateData);
            }
            catch (Exception ex) when (ex is ArgumentException || ex is MarshalDirectiveException ||
                                       ex is SEHException || ex is DllNotFoundException ||
                                       ex is EntryPointNotFoundException || ex is BadImageFormatException ||
                                       ex is CryptographicException)
            {
                return null;
            }
            finally
            {
                if (trustDataPointer != IntPtr.Zero)
                {
                    try
                    {
                        var trustData = (WinTrustData)Marshal.PtrToStructure(
                            trustDataPointer, typeof(WinTrustData));
                        trustData.StateAction = StateActionClose;
                        Marshal.StructureToPtr(trustData, trustDataPointer, false);
                        var action = VerifyAction;
                        nativeApi.VerifyTrust(new IntPtr(-1), ref action, trustDataPointer);
                    }
                    catch
                    {
                    }
                    Marshal.FreeHGlobal(trustDataPointer);
                }
                if (fileInfoPointer != IntPtr.Zero)
                    Marshal.FreeHGlobal(fileInfoPointer);
                if (signatureSettingsPointer != IntPtr.Zero)
                    Marshal.FreeHGlobal(signatureSettingsPointer);
                if (pathPointer != IntPtr.Zero)
                    Marshal.FreeCoTaskMem(pathPointer);
            }
        }

        private static X509Certificate2 GetLegacyVerifiedSignerCertificate(string path)
        {
            WinTrustApi nativeApi;
            if (!TryGetNativeApi(out nativeApi))
                return null;

            IntPtr pathPointer = IntPtr.Zero;
            IntPtr fileInfoPointer = IntPtr.Zero;
            IntPtr trustDataPointer = IntPtr.Zero;
            try
            {
                pathPointer = Marshal.StringToCoTaskMemUni(path);
                var fileInfo = new WinTrustFileInfo
                {
                    StructSize = (uint)Marshal.SizeOf(typeof(WinTrustFileInfo)),
                    FilePath = pathPointer
                };
                fileInfoPointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WinTrustFileInfo)));
                Marshal.StructureToPtr(fileInfo, fileInfoPointer, false);

                var trustData = new LegacyWinTrustData
                {
                    StructSize = (uint)Marshal.SizeOf(typeof(LegacyWinTrustData)),
                    UiChoice = TrustUiNone,
                    RevocationChecks = RevokeNone,
                    UnionChoice = ChoiceFile,
                    FileInfo = fileInfoPointer,
                    StateAction = StateActionVerify,
                    ProviderFlags = CacheOnlyUrlRetrieval
                };
                trustDataPointer = Marshal.AllocHGlobal(
                    Marshal.SizeOf(typeof(LegacyWinTrustData)));
                Marshal.StructureToPtr(trustData, trustDataPointer, false);

                var action = VerifyAction;
                if (nativeApi.VerifyTrust(new IntPtr(-1), ref action, trustDataPointer) != 0)
                    return null;
                trustData = (LegacyWinTrustData)Marshal.PtrToStructure(
                    trustDataPointer, typeof(LegacyWinTrustData));
                return GetSignerCertificateFromState(nativeApi, trustData.StateData);
            }
            catch (Exception ex) when (ex is ArgumentException || ex is MarshalDirectiveException ||
                                       ex is SEHException || ex is DllNotFoundException ||
                                       ex is EntryPointNotFoundException || ex is BadImageFormatException ||
                                       ex is CryptographicException)
            {
                return null;
            }
            finally
            {
                if (trustDataPointer != IntPtr.Zero)
                {
                    try
                    {
                        var trustData = (LegacyWinTrustData)Marshal.PtrToStructure(
                            trustDataPointer, typeof(LegacyWinTrustData));
                        trustData.StateAction = StateActionClose;
                        Marshal.StructureToPtr(trustData, trustDataPointer, false);
                        var action = VerifyAction;
                        nativeApi.VerifyTrust(new IntPtr(-1), ref action, trustDataPointer);
                    }
                    catch
                    {
                    }
                    Marshal.FreeHGlobal(trustDataPointer);
                }
                if (fileInfoPointer != IntPtr.Zero)
                    Marshal.FreeHGlobal(fileInfoPointer);
                if (pathPointer != IntPtr.Zero)
                    Marshal.FreeCoTaskMem(pathPointer);
            }
        }

        private static bool TryGetNativeApi(out WinTrustApi nativeApi)
        {
            try
            {
                nativeApi = NativeApi.Value;
                return nativeApi != null;
            }
            catch
            {
                // Native loader/export failures are integrity failures, not a reason to fall back
                // to the default application-directory DLL search order.
                nativeApi = null;
                return false;
            }
        }

        private static X509Certificate2 GetSignerCertificateFromState(WinTrustApi nativeApi,
            IntPtr stateData)
        {
            if (stateData == IntPtr.Zero)
                return null;
            var providerData = nativeApi.ProviderDataFromStateData(stateData);
            if (providerData == IntPtr.Zero)
                return null;
            var signer = nativeApi.GetProviderSignerFromChain(providerData, 0, false, 0);
            if (signer == IntPtr.Zero)
                return null;
            var providerCertificate = nativeApi.GetProviderCertificateFromChain(signer, 0);
            if (providerCertificate == IntPtr.Zero)
                return null;
            var certificateData = (CryptProviderCertificate)Marshal.PtrToStructure(
                providerCertificate, typeof(CryptProviderCertificate));
            if (certificateData.CertificateContext == IntPtr.Zero)
                return null;

            using (var certificate = new X509Certificate2(certificateData.CertificateContext))
                return new X509Certificate2(certificate.RawData);
        }

        [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode,
            SetLastError = true)]
        private static extern IntPtr LoadLibraryExW(string fileName, IntPtr file,
            uint flags);

        [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Ansi,
            SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr module, string procedureName);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FreeLibrary(IntPtr module);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate int WinVerifyTrustFunction(IntPtr windowHandle, ref Guid actionId,
            IntPtr trustData);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate IntPtr ProviderDataFromStateDataFunction(IntPtr stateData);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate IntPtr GetProviderSignerFromChainFunction(IntPtr providerData,
            uint signerIndex, [MarshalAs(UnmanagedType.Bool)] bool counterSigner,
            uint counterSignerIndex);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate IntPtr GetProviderCertificateFromChainFunction(IntPtr signer,
            uint certificateIndex);

        private sealed class WinTrustApi
        {
            // Retaining this object for the process lifetime also retains the HMODULE backing
            // every delegate. Unloading it while verification is in flight would be unsafe.
            private readonly IntPtr _module;

            private WinTrustApi(IntPtr module)
            {
                _module = module;
                VerifyTrust = (WinVerifyTrustFunction)GetRequiredExport(module,
                    "WinVerifyTrust", typeof(WinVerifyTrustFunction));
                ProviderDataFromStateData =
                    (ProviderDataFromStateDataFunction)GetRequiredExport(module,
                        "WTHelperProvDataFromStateData", typeof(ProviderDataFromStateDataFunction));
                GetProviderSignerFromChain =
                    (GetProviderSignerFromChainFunction)GetRequiredExport(module,
                        "WTHelperGetProvSignerFromChain",
                        typeof(GetProviderSignerFromChainFunction));
                GetProviderCertificateFromChain =
                    (GetProviderCertificateFromChainFunction)GetRequiredExport(module,
                        "WTHelperGetProvCertFromChain",
                        typeof(GetProviderCertificateFromChainFunction));
            }

            public WinVerifyTrustFunction VerifyTrust { get; }
            public ProviderDataFromStateDataFunction ProviderDataFromStateData { get; }
            public GetProviderSignerFromChainFunction GetProviderSignerFromChain { get; }
            public GetProviderCertificateFromChainFunction GetProviderCertificateFromChain { get; }

            public static WinTrustApi Load()
            {
                var systemDirectory = Environment.SystemDirectory;
                if (string.IsNullOrWhiteSpace(systemDirectory) ||
                    !Path.IsPathRooted(systemDirectory))
                    throw new DllNotFoundException("The Windows system directory is unavailable.");

                var winTrustPath = Path.Combine(systemDirectory, "wintrust.dll");
                var module = LoadLibraryExW(winTrustPath, IntPtr.Zero,
                    LoadLibrarySearchSystem32);
                if (module == IntPtr.Zero && Marshal.GetLastWin32Error() == ErrorInvalidParameter)
                {
                    // Unpatched Windows 7 does not recognize LOAD_LIBRARY_SEARCH_SYSTEM32.
                    // An absolute path plus LOAD_WITH_ALTERED_SEARCH_PATH makes System32 the
                    // dependency origin without consulting the application directory first.
                    module = LoadLibraryExW(winTrustPath, IntPtr.Zero,
                        LoadWithAlteredSearchPath);
                }
                if (module == IntPtr.Zero)
                {
                    throw new DllNotFoundException(
                        "The Windows System32 WinTrust library could not be loaded (Win32 error " +
                        Marshal.GetLastWin32Error() + ").");
                }

                try
                {
                    return new WinTrustApi(module);
                }
                catch
                {
                    FreeLibrary(module);
                    throw;
                }
            }

            private static Delegate GetRequiredExport(IntPtr module, string name,
                Type delegateType)
            {
                var address = GetProcAddress(module, name);
                if (address == IntPtr.Zero)
                    throw new EntryPointNotFoundException(
                        "The Windows System32 WinTrust library does not export '" + name + "'.");
                return Marshal.GetDelegateForFunctionPointer(address, delegateType);
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WinTrustFileInfo
        {
            public uint StructSize;
            public IntPtr FilePath;
            public IntPtr FileHandle;
            public IntPtr KnownSubject;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WinTrustData
        {
            public uint StructSize;
            public IntPtr PolicyCallbackData;
            public IntPtr SipClientData;
            public uint UiChoice;
            public uint RevocationChecks;
            public uint UnionChoice;
            public IntPtr FileInfo;
            public uint StateAction;
            public IntPtr StateData;
            public IntPtr UrlReference;
            public uint ProviderFlags;
            public uint UiContext;
            public IntPtr SignatureSettings;
        }

        // Windows 7 predates WINTRUST_DATA.pSignatureSettings. Passing the newer structure size
        // causes its WinVerifyTrust implementation to reject otherwise valid signed binaries.
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct LegacyWinTrustData
        {
            public uint StructSize;
            public IntPtr PolicyCallbackData;
            public IntPtr SipClientData;
            public uint UiChoice;
            public uint RevocationChecks;
            public uint UnionChoice;
            public IntPtr FileInfo;
            public uint StateAction;
            public IntPtr StateData;
            public IntPtr UrlReference;
            public uint ProviderFlags;
            public uint UiContext;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WinTrustSignatureSettings
        {
            public uint StructSize;
            public uint Index;
            public uint Flags;
            public uint SecondarySignatureCount;
            public uint VerifiedSignatureIndex;
            public IntPtr CryptoPolicy;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CryptProviderCertificate
        {
            public uint StructSize;
            public IntPtr CertificateContext;
        }
    }
}
