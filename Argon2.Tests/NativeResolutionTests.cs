using System;
using System.Security.Cryptography;
using Xunit;

namespace Argon2Tests;

/// <summary>
/// Runs a fact only when ARGON2_TEST_MODE matches, otherwise reports it as skipped. xunit v2 has
/// no runtime skip, so the decision is made at discovery time.
/// </summary>
public sealed class NativeModeFactAttribute : FactAttribute
{
    public const string ModeVariable = "ARGON2_TEST_MODE";

    public NativeModeFactAttribute(string mode, string requires)
    {
        if (Environment.GetEnvironmentVariable(ModeVariable) != mode)
        {
            Skip = $"Requires {ModeVariable}={mode} ({requires}).";
        }
    }
}

/// <summary>
/// Native resolution depends entirely on which packages exist on the machine, so these only run
/// inside the CI containers that control that. On a dev box the package bundles libargon2.dll or
/// libargon2.dylib and resolution never reaches the versioned-SONAME path, so running them there
/// would prove nothing.
/// </summary>
public class NativeResolutionTests
{
    private const string Password = "correct horse battery staple";

    /// <summary>
    /// The bug this whole change exists to fix: libargon2.so.1 is installed and loadable, but
    /// DllImport never asks for a versioned SONAME, so only the -dev package's unversioned symlink
    /// made resolution work.
    /// </summary>
    [NativeModeFact("runtime-only", "container with libargon2-1 and no -dev")]
    public void RuntimePackageOnly_ResolvesViaVersionedSoname() => AssertHashesAndVerifies();

    /// <summary>
    /// Regression guard for servers already set up the documented way. With the unversioned symlink
    /// present, resolution must still succeed on the plain-name step and never reach the versioned
    /// probe.
    /// </summary>
    [NativeModeFact("dev", "container with libargon2-dev")]
    public void DevPackageInstalled_StillResolves() => AssertHashesAndVerifies();

    [NativeModeFact("missing", "container with no libargon2 at all")]
    public void NoNativeLibrary_ThrowsWithRuntimePackageInstructions()
    {
        var exception = Record.Exception(() => new Argon2PasswordHasher().Hash(Password));

        var dllNotFound = Unwrap<DllNotFoundException>(exception);
        Assert.NotNull(dllNotFound);

        // Names the runtime package, so an operator is not sent to install -dev.
        Assert.Contains("libargon2-1", dllNotFound.Message, StringComparison.Ordinal);
        // Says what was actually tried, so this reads as a missing package and not a broken build.
        // The range is stated rather than each name: argon2's real SONAME is .so.1 while
        // libdeflate's is .so.0 on the same machine, which is why a range is probed at all.
        Assert.Contains("libargon2.so.0 through libargon2.so.9", dllNotFound.Message, StringComparison.Ordinal);
        // Says outright that -dev is not the answer.
        Assert.Contains("-dev", dllNotFound.Message, StringComparison.Ordinal);
    }

    private static void AssertHashesAndVerifies()
    {
        var hasher = new Argon2PasswordHasher();

        var hashed = hasher.Hash(Password);

        Assert.True(hasher.Verify(hashed, Password));
        Assert.False(hasher.Verify(hashed, "not the password"));
    }

    private static T? Unwrap<T>(Exception? exception) where T : Exception
    {
        for (var current = exception; current is not null; current = current.InnerException)
        {
            if (current is T match)
            {
                return match;
            }
        }

        return null;
    }
}
