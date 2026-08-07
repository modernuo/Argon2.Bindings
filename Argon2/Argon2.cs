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

    /// <summary>
    /// Highest libargon2.so.N suffix probed on Linux. argon2 has been .so.1 everywhere we checked
    /// (Debian, Ubuntu, Fedora, Alpine) while libdeflate is .so.0 on the same machines -- the digit
    /// is per library and per distro, not a convention, which is why a range is probed.
    /// </summary>
    private const int MaxSoVersion = 9;

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

        // The loader's own search path, unversioned. This is what an install with the -dev package
        // resolves on, so it stays ahead of the versioned probe below.
        if (NativeLibrary.TryLoad(libName, assembly, searchPath, out var handle))
        {
            return handle;
        }

        // Linux ships libargon2.so.N and only the -dev package adds the unversioned symlink the
        // step above needs. Probe versions by bare name so this still goes through the full loader
        // search path (LD_LIBRARY_PATH, /etc/ld.so.conf.d). Descending prefers the newest ABI.
        if (OperatingSystem.IsLinux())
        {
            for (var soVersion = MaxSoVersion; soVersion >= 0; soVersion--)
            {
                if (NativeLibrary.TryLoad($"{AssemblyName}.so.{soVersion}", assembly, searchPath, out handle))
                {
                    return handle;
                }
            }
        }

        // Homebrew on Apple Silicon is off the default dyld search path.
        if (OperatingSystem.IsMacOS() &&
            RuntimeInformation.ProcessArchitecture == Architecture.Arm64 &&
            NativeLibrary.TryLoad($"/opt/homebrew/lib/{OSXAssemblyName}", out handle))
        {
            return handle;
        }

        throw new DllNotFoundException(BuildNotFoundMessage());
    }

    private static string BuildNotFoundMessage()
    {
        if (OperatingSystem.IsLinux())
        {
            return $"""
                   Could not load {AssemblyName}. Tried {UnixAssemblyName} and {AssemblyName}.so.0 through {AssemblyName}.so.{MaxSoVersion} on the loader path, and runtimes/{GetRuntimeIdentifier()}/native/ next to the assembly.

                   Install the runtime library. The -dev package is NOT required:
                     Debian/Ubuntu   sudo apt-get install -y libargon2-1
                     Fedora/RHEL     sudo dnf install -y libargon2
                     Alpine          apk add argon2-libs
                   """;
        }

        if (OperatingSystem.IsMacOS())
        {
            return $"Could not load {AssemblyName}. Install it with: brew install argon2";
        }

        return $"Could not load {AssemblyName}. The bundled runtimes/{GetRuntimeIdentifier()}/native/{GetPlatformLibraryName()} is missing from the package.";
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
