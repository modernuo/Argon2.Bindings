using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Xunit;
using Xunit.Abstractions;

namespace Argon2Tests;

/// <summary>
/// Regression tests for the SkipLocalsInit hardening. The Argon2 library is
/// compiled with [module: SkipLocalsInit], so its stackalloc buffers are NOT
/// implicitly zeroed. These tests dirty the stack with non-zero bytes
/// immediately before calling into the library, which makes any reliance on
/// implicit zeroing fail deterministically instead of intermittently.
/// </summary>
public class SkipLocalsInitTests
{
    private readonly ITestOutputHelper _output;
    public SkipLocalsInitTests(ITestOutputHelper output) => _output = output;

    // Fills a chunk of the stack with 0xFF so that subsequent stackalloc'd
    // buffers (in the library, if it relied on zeroing) would observe garbage.
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static int DirtyStack()
    {
        Span<byte> scratch = stackalloc byte[8192];
        scratch.Fill(0xFF);
        var sum = 0;
        foreach (var b in scratch)
        {
            sum += b;
        }
        return sum;
    }

    [Fact]
    public void Verify_AfterDirtyStack_AlwaysSucceedsForCorrectPassword()
    {
        var hasher = new Argon2PasswordHasher();
        const string password = "fernando";

        var failures = 0;
        for (var i = 0; i < 200; i++)
        {
            var hash = hasher.Hash(password);
            _ = DirtyStack();
            if (!hasher.Verify(hash, password))
            {
                failures++;
            }
        }

        _output.WriteLine($"verify failures after dirty stack: {failures}/200");
        Assert.Equal(0, failures);
    }

    [Fact]
    public void Hash_AfterDirtyStack_ProducesCleanStringWithoutTrailingGarbage()
    {
        var hasher = new Argon2PasswordHasher();
        const string password = "fernando";

        for (var i = 0; i < 200; i++)
        {
            _ = DirtyStack();
            var hash = hasher.Hash(password);

            Assert.DoesNotContain('\0', hash);
            Assert.StartsWith("$argon2i$", hash);
            // Last char must be a valid Base64 character, not stack garbage.
            var last = hash[^1];
            var validTail = char.IsLetterOrDigit(last) || last is '+' or '/' or '=';
            Assert.True(validTail, $"unexpected trailing char '{(int)last}' in: {hash}");
            Assert.True(hasher.Verify(hash, password));
        }
    }
}
