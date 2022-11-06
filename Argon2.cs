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
    public static Argon2Error Hash(uint t_cost, uint m_cost, uint parallelism,
        ReadOnlySpan<byte> pwd,
        ReadOnlySpan<byte> salt,
        Span<byte> hash,
        Span<byte> encoded,
        int type, int version) =>
        argon2_hash(t_cost, m_cost, parallelism,
            in pwd.GetPinnableReference(), pwd.Length,
            in salt.GetPinnableReference(), salt.Length,
            ref hash.GetPinnableReference(), hash.Length,
            ref encoded.GetPinnableReference(), encoded.Length,
            type, version
        );

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Argon2Error Verify(ReadOnlySpan<byte> encoded, ReadOnlySpan<byte> pwd, int pwdlen, int type) =>
        argon2_verify(in encoded.GetPinnableReference(), in pwd.GetPinnableReference(), pwdlen, type);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Argon2Error Decode(Argon2Context ctx, ReadOnlySpan<byte> str, int type) =>
        decode_string(ctx, in str.GetPinnableReference(), type);

    [DllImport("libargon2", EntryPoint = "argon2_hash")]
    internal static extern Argon2Error argon2_hash(uint t_cost, uint m_cost, uint parallelism,
        in byte pwd, int pwdlen,
        in byte salt, int saltlen,
        ref byte hash, int hashlen,
        ref byte encoded, int encodedlen,
        int type, int version
    );

    [DllImport("libargon2", EntryPoint = "argon2_verify")]
    internal static extern Argon2Error argon2_verify(in byte encoded, in byte pwd, int pwdlen, int type);

    [DllImport("libargon2", EntryPoint = "decode_string")]
    internal static extern Argon2Error decode_string(Argon2Context ctx, in byte str, int type);
}
