using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace System.Security.Cryptography;

public static class Argon2
{
    public const string AssemblyName = "libargon2";
    public const string WindowsAssemblyName = $"{AssemblyName}.dll";
    public const string OSXAssemblyName = $"{AssemblyName}.dylib";
    public const string UnixAssemblyName = $"{AssemblyName}.so";

    static Argon2() => NativeLibrary.SetDllImportResolver(Assembly.GetExecutingAssembly(), DllImportResolver);

    private static IntPtr DllImportResolver(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName != AssemblyName)
        {
            return IntPtr.Zero;
        }

        var libName = GetPlatformLibraryName();
        var assemblyLocation = assembly.Location;

        if (!string.IsNullOrEmpty(assemblyLocation))
        {
            var assemblyDir = Path.GetDirectoryName(assemblyLocation);
            if (assemblyDir != null)
            {
                // Try runtimes/{rid}/native/ folder (standard NuGet layout for non-published builds)
                var runtimesPath = Path.Combine(assemblyDir, "runtimes", GetRuntimeIdentifier(), "native", libName);
                if (File.Exists(runtimesPath) && NativeLibrary.TryLoad(runtimesPath, out var runtimesHandle))
                {
                    return runtimesHandle;
                }

                // Try directly next to assembly (published apps)
                var bundledPath = Path.Combine(assemblyDir, libName);
                if (File.Exists(bundledPath) && NativeLibrary.TryLoad(bundledPath, out var bundledHandle))
                {
                    return bundledHandle;
                }
            }
        }

        // Default resolution
        if (NativeLibrary.TryLoad(libName, assembly, searchPath, out var handle))
        {
            return handle;
        }

        if (NativeLibrary.TryLoad(libraryName, assembly, searchPath, out handle))
        {
            return handle;
        }

        // macOS ARM64: Try Homebrew path
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX) &&
            RuntimeInformation.ProcessArchitecture == Architecture.Arm64)
        {
            if (NativeLibrary.TryLoad($"/opt/homebrew/lib/{AssemblyName}.dylib", out handle))
            {
                return handle;
            }
        }

        throw new DllNotFoundException(
            $"Could not load {libraryName}. " +
            (RuntimeInformation.IsOSPlatform(OSPlatform.OSX)
                ? "On macOS, install via: brew install argon2"
                : "Ensure libargon2 is installed on your system."));
    }

    private static string GetPlatformLibraryName() =>
        RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? WindowsAssemblyName :
        RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? OSXAssemblyName :
        UnixAssemblyName;

    private static string GetRuntimeIdentifier()
    {
        var os = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "win" :
            RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "osx" : "linux";

        var arch = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => "x64",
            Architecture.Arm64 => "arm64",
            Architecture.X86 => "x86",
            Architecture.Arm => "arm",
            _ => "x64"
        };

        return $"{os}-{arch}";
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
}
