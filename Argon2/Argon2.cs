using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace System.Security.Cryptography;

public static class Argon2
{
    public const string WindowsAssemblyName = "libargon2.dll";
    // Unix adds the word lib in front as one of the resolutions
    public const string UnixAssemblyName = "libargon2";

    static Argon2() => NativeLibrary.SetDllImportResolver(Assembly.GetExecutingAssembly(), DllImportResolver);

    public static string GetLibraryName(string libraryName) => Environment.OSVersion.Platform switch
    {
        PlatformID.Win32NT => WindowsAssemblyName,
        _                  => UnixAssemblyName,
    };

    public static IntPtr DllImportResolver(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        var platformDependentName = GetLibraryName(libraryName);
        if (NativeLibrary.TryLoad(platformDependentName, assembly, searchPath, out var handle))
        {
            return handle;
        }

        throw new BadImageFormatException("Could not load the libargon2 native library.");
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe Argon2Error Hash(uint t_cost, uint m_cost, uint parallelism,
        ReadOnlySpan<byte> pwd,
        ReadOnlySpan<byte> salt,
        Span<byte> hash,
        Span<byte> encoded,
        int type, int version)
    {
        fixed (byte* p_pwd = pwd, p_salt = salt, p_hash = hash, p_encoded = encoded)
        {
            return argon2_hash(
                t_cost,
                m_cost,
                parallelism,
                p_pwd,
                pwd.Length,
                p_salt,
                salt.Length,
                p_hash,
                hash.Length,
                p_encoded,
                encoded.Length,
                type,
                version
            );
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe Argon2Error Verify(ReadOnlySpan<byte> encoded, ReadOnlySpan<byte> pwd, long pwdlen, int type)
    {
        fixed (byte* p_pwd = pwd, p_encoded = encoded)
        {
            return argon2_verify(p_encoded, p_pwd, pwdlen, type);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe Argon2Error Decode(Argon2Context ctx, ReadOnlySpan<byte> str, int type)
    {
        fixed (byte* p_str = str)
        {
            return decode_string(ctx, p_str, type);
        }
    }

    [DllImport("libargon2", EntryPoint = "argon2_hash")]
    internal static extern unsafe Argon2Error argon2_hash(uint t_cost, uint m_cost, uint parallelism,
        byte* pwd, long pwdlen,
        byte* salt, long saltlen,
        byte* hash, long hashlen,
        byte* encoded, long encodedlen,
        int type, int version
    );

    [DllImport("libargon2", EntryPoint = "argon2_verify")]
    internal static extern unsafe Argon2Error argon2_verify(byte* encoded, byte* pwd, long pwdlen, int type);

    [DllImport("libargon2", EntryPoint = "decode_string")]
    internal static extern unsafe Argon2Error decode_string(Argon2Context ctx, byte* str, int type);
}
