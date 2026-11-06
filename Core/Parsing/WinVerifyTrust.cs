using System.Runtime.InteropServices;

namespace Core.Parsing;

internal enum WinVerifyTrustOutcome
{
    NotAvailable,
    Trusted,
    BadDigest,
    OtherFailure
}

/// <summary>
/// Optional Windows-native Authenticode cross-check. It never performs network retrieval.
/// </summary>
internal static class WinVerifyTrust
{
    private const uint WtdUiNone = 2;
    private const uint WtdRevokeNone = 0;
    private const uint WtdChoiceFile = 1;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdRevocationCheckNone = 0x10;
    private const uint WtdCacheOnlyUrlRetrieval = 0x1000;
    private const uint TrustEBadDigest = 0x80096010;

    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    public static WinVerifyTrustOutcome TryVerify(string? filePath, out string? error)
    {
        error = null;
        if (string.IsNullOrWhiteSpace(filePath) || !OperatingSystem.IsWindows())
        {
            return WinVerifyTrustOutcome.NotAvailable;
        }

        IntPtr fileInfoPtr = IntPtr.Zero;
        IntPtr dataPtr = IntPtr.Zero;

        try
        {
            var fileInfo = new WinTrustFileInfo
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
                pcwszFilePath = filePath,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero
            };

            fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, fDeleteOld: false);

            var data = new WinTrustData
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
                pPolicyCallbackData = IntPtr.Zero,
                pSIPClientData = IntPtr.Zero,
                dwUIChoice = WtdUiNone,
                fdwRevocationChecks = WtdRevokeNone,
                dwUnionChoice = WtdChoiceFile,
                pFile = fileInfoPtr,
                dwStateAction = WtdStateActionVerify,
                hWVTStateData = IntPtr.Zero,
                pwszURLReference = IntPtr.Zero,
                dwProvFlags = WtdRevocationCheckNone | WtdCacheOnlyUrlRetrieval,
                dwUIContext = 0,
                pSignatureSettings = IntPtr.Zero
            };

            dataPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustData>());
            Marshal.StructureToPtr(data, dataPtr, fDeleteOld: false);

            uint result = WinVerifyTrustNative(IntPtr.Zero, GenericVerifyV2, dataPtr);

            data.dwStateAction = WtdStateActionClose;
            Marshal.StructureToPtr(data, dataPtr, fDeleteOld: false);
            _ = WinVerifyTrustNative(IntPtr.Zero, GenericVerifyV2, dataPtr);

            if (result == 0)
            {
                return WinVerifyTrustOutcome.Trusted;
            }

            if (result == TrustEBadDigest)
            {
                error = "WinVerifyTrust reported a bad digest.";
                return WinVerifyTrustOutcome.BadDigest;
            }

            error = $"WinVerifyTrust returned 0x{result:X8}.";
            return WinVerifyTrustOutcome.OtherFailure;
        }
        catch (Exception ex)
        {
            error = $"WinVerifyTrust failed: {ex.Message}";
            return WinVerifyTrustOutcome.OtherFailure;
        }
        finally
        {
            if (fileInfoPtr != IntPtr.Zero)
            {
                Marshal.DestroyStructure<WinTrustFileInfo>(fileInfoPtr);
                Marshal.FreeHGlobal(fileInfoPtr);
            }

            if (dataPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(dataPtr);
            }
        }
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint WinVerifyTrustNative(
        IntPtr hwnd,
        [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID,
        IntPtr pWVTData);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public uint cbStruct;
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustData
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }
}
