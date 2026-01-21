using System;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Argon2Tests;

public class HashAndVerifyTests
{
    [Fact]
    public void Hash_AndVerify_WithValidPassword_ReturnsTrue()
    {
        var hasher = new Argon2PasswordHasher();
        const string password = "123456789";

        var encryptedPassword = hasher.Hash(password);
        var verifyResult = hasher.Verify(encryptedPassword, password);

        Assert.True(verifyResult);
    }

    [Fact]
    public void Verify_WithWrongPassword_ReturnsFalse()
    {
        var hasher = new Argon2PasswordHasher();
        const string password = "correctpassword";
        const string wrongPassword = "wrongpassword";

        var encryptedPassword = hasher.Hash(password);
        var verifyResult = hasher.Verify(encryptedPassword, wrongPassword);

        Assert.False(verifyResult);
    }

    [Fact]
    public void Hash_WithEmptyPassword_Works()
    {
        var hasher = new Argon2PasswordHasher();
        const string password = "";

        var encryptedPassword = hasher.Hash(password);
        Assert.True(hasher.Verify(encryptedPassword, password));
        Assert.False(hasher.Verify(encryptedPassword, "notempty"));
    }

    [Fact]
    public void Hash_WithUnicodePassword_Works()
    {
        var hasher = new Argon2PasswordHasher();
        const string password = "пароль密码🔐";

        var encryptedPassword = hasher.Hash(password);

        Assert.True(hasher.Verify(encryptedPassword, password));
        Assert.False(hasher.Verify(encryptedPassword, "wrongpassword"));
    }

    [Fact]
    public void Hash_WithLongPassword_Works()
    {
        var hasher = new Argon2PasswordHasher();
        var password = new string('a', 1000);

        var encryptedPassword = hasher.Hash(password);

        Assert.True(hasher.Verify(encryptedPassword, password));
    }

    [Fact]
    public void Hash_WithCustomSalt_ProducesDeterministicResult()
    {
        var hasher = new Argon2PasswordHasher();
        const string password = "testpassword";
        var salt = new byte[16];
        Array.Fill(salt, (byte)0x42);

        var hash1 = hasher.Hash(password, salt);
        var hash2 = hasher.Hash(password, salt);

        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void Hash_WithDifferentSalts_ProducesDifferentResults()
    {
        var hasher = new Argon2PasswordHasher();
        const string password = "testpassword";

        var hash1 = hasher.Hash(password);
        var hash2 = hasher.Hash(password);

        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void Hash_WithByteSpanOverload_Works()
    {
        var hasher = new Argon2PasswordHasher();
        var password = Encoding.UTF8.GetBytes("testpassword");
        var salt = new byte[16];
        RandomNumberGenerator.Fill(salt);
        var hash = new byte[32];

        var result = hasher.Hash(password, salt, hash);

        Assert.NotNull(result);
        Assert.StartsWith("$argon2i$", result);
    }
}

public class TryExtractMetadataValuesTests
{
    [Fact]
    public void TryExtractMetadataValues_Argon2i_ParsesCorrectly()
    {
        var hasher = new Argon2PasswordHasher(
            time: 3,
            memory: 8192,
            parallel: 2,
            type: Argon2Type.Argon2i,
            hashLength: 32,
            saltLength: 16
        );

        var encryptedPassword = hasher.Hash("testpassword");
        var success = Argon2PasswordHasher.TryExtractMetadataValues(encryptedPassword, out var values);

        Assert.True(success);
        Assert.Equal(Argon2Type.Argon2i, values.ArgonType);
        Assert.Equal(8192u, values.MemoryCost);
        Assert.Equal(3u, values.TimeCost);
        Assert.Equal(2u, values.Parallelism);
        Assert.Equal(16, values.SaltLength);
        Assert.Equal(32, values.HashLength);
    }

    [Fact]
    public void TryExtractMetadataValues_Argon2d_ParsesCorrectly()
    {
        var hasher = new Argon2PasswordHasher(
            time: 2,
            memory: 4096,
            parallel: 1,
            type: Argon2Type.Argon2d,
            hashLength: 32,
            saltLength: 16
        );

        var encryptedPassword = hasher.Hash("testpassword");
        var success = Argon2PasswordHasher.TryExtractMetadataValues(encryptedPassword, out var values);

        Assert.True(success);
        Assert.Equal(Argon2Type.Argon2d, values.ArgonType);
        Assert.Equal(4096u, values.MemoryCost);
        Assert.Equal(2u, values.TimeCost);
        Assert.Equal(1u, values.Parallelism);
    }

    [Fact]
    public void TryExtractMetadataValues_Argon2id_ParsesCorrectly()
    {
        var hasher = new Argon2PasswordHasher(
            time: 4,
            memory: 65536,
            parallel: 4,
            type: Argon2Type.Argon2id
        );

        var encryptedPassword = hasher.Hash("anotherpassword");
        var success = Argon2PasswordHasher.TryExtractMetadataValues(encryptedPassword, out var values);

        Assert.True(success);
        Assert.Equal(Argon2Type.Argon2id, values.ArgonType);
        Assert.Equal(65536u, values.MemoryCost);
        Assert.Equal(4u, values.TimeCost);
        Assert.Equal(4u, values.Parallelism);
    }

    [Fact]
    public void TryExtractMetadataValues_WithCustomLengths_ParsesCorrectly()
    {
        var hasher = new Argon2PasswordHasher(
            hashLength: 64,
            saltLength: 32
        );

        var encryptedPassword = hasher.Hash("password");
        var success = Argon2PasswordHasher.TryExtractMetadataValues(encryptedPassword, out var values);

        Assert.True(success);
        Assert.Equal(32, values.SaltLength);
        Assert.Equal(64, values.HashLength);
    }

    [Theory]
    [InlineData("")]
    [InlineData("invalid")]
    [InlineData("$argon2x$v=19$m=1,t=1,p=1$AAAA$AAAA")]
    [InlineData("$argon2i$v=19$m=0,t=1,p=1$AAAA$AAAA")]
    [InlineData("$argon2i$v=19$m=1,t=0,p=1$AAAA$AAAA")]
    [InlineData("$argon2i$v=19$m=1,t=1,p=0$AAAA$AAAA")]
    [InlineData("$argon2i$v=19$AAAA$AAAA")]
    [InlineData("short")]
    public void TryExtractMetadataValues_WithInvalidInput_ReturnsFalse(string invalidHash)
    {
        Assert.False(Argon2PasswordHasher.TryExtractMetadataValues(invalidHash, out _));
    }

    [Fact]
    public void TryExtractMetadataValues_CalculatesCorrectBase64DecodedLengths()
    {
        // Test various salt/hash lengths to ensure Base64 length calculation is correct
        foreach (var saltLen in new uint[] { 8, 12, 16, 24, 32 })
        {
            foreach (var hashLen in new uint[] { 16, 24, 32, 48, 64 })
            {
                var hasher = new Argon2PasswordHasher(saltLength: saltLen, hashLength: hashLen);
                var hash = hasher.Hash("test");

                Assert.True(Argon2PasswordHasher.TryExtractMetadataValues(hash, out var values));
                Assert.Equal((int)saltLen, values.SaltLength);
                Assert.Equal((int)hashLen, values.HashLength);
            }
        }
    }
}

public class TryExtractMetadataSpanTests
{
    [Fact]
    public void TryExtractMetadata_WithSpans_ExtractsCorrectData()
    {
        var hasher = new Argon2PasswordHasher(
            time: 2,
            memory: 16384,
            parallel: 2,
            type: Argon2Type.Argon2i,
            hashLength: 32,
            saltLength: 16
        );

        var encryptedPassword = hasher.Hash("spantestpassword");

        Assert.True(Argon2PasswordHasher.TryExtractMetadataValues(encryptedPassword, out var values));

        Span<byte> salt = stackalloc byte[values.SaltLength];
        Span<byte> hash = stackalloc byte[values.HashLength];

        Argon2PasswordHasher.TryExtractMetadata(encryptedPassword, salt, hash);

        // Verify salt and hash contain actual data (not all zeros)
        Assert.False(salt.SequenceEqual(new byte[16]));
        Assert.False(hash.SequenceEqual(new byte[32]));
    }

    [Fact]
    public void TryExtractMetadata_SaltCanBeUsedToRehash()
    {
        var hasher = new Argon2PasswordHasher(
            time: 2,
            memory: 4096,
            parallel: 1
        );
        const string password = "testpassword";

        var originalHash = hasher.Hash(password);

        Assert.True(Argon2PasswordHasher.TryExtractMetadataValues(originalHash, out var values));

        Span<byte> salt = stackalloc byte[values.SaltLength];
        Span<byte> hash = stackalloc byte[values.HashLength];
        Argon2PasswordHasher.TryExtractMetadata(originalHash, salt, hash);

        // Rehash with same salt should produce same result
        var rehashed = hasher.Hash(password, salt);

        Assert.Equal(originalHash, rehashed);
    }

    [Fact]
    public void TryExtractMetadata_ExtractedValuesAreConsistent()
    {
        var hasher = new Argon2PasswordHasher();
        var encryptedPassword = hasher.Hash("test");

        Assert.True(Argon2PasswordHasher.TryExtractMetadataValues(encryptedPassword, out var values));

        Span<byte> salt1 = stackalloc byte[values.SaltLength];
        Span<byte> hash1 = stackalloc byte[values.HashLength];
        Argon2PasswordHasher.TryExtractMetadata(encryptedPassword, salt1, hash1);

        Span<byte> salt2 = stackalloc byte[values.SaltLength];
        Span<byte> hash2 = stackalloc byte[values.HashLength];
        Argon2PasswordHasher.TryExtractMetadata(encryptedPassword, salt2, hash2);

        Assert.True(salt1.SequenceEqual(salt2));
        Assert.True(hash1.SequenceEqual(hash2));
    }
}

public class VerifyAndUpdateTests
{
    [Fact]
    public void VerifyAndUpdate_WhenParametersMatch_DoesNotUpdate()
    {
        var hasher = new Argon2PasswordHasher(
            time: 3,
            memory: 8192,
            parallel: 2
        );
        const string password = "testpassword";

        var originalHash = hasher.Hash(password);

        // Same hasher, same parameters
        var verified = hasher.VerifyAndUpdate(originalHash, password, out var isUpdated, out var newHash);

        Assert.True(verified);
        Assert.False(isUpdated);
        Assert.Equal(originalHash, newHash);
    }

    [Fact]
    public void VerifyAndUpdate_WhenParametersDiffer_Updates()
    {
        var oldHasher = new Argon2PasswordHasher(
            time: 2,
            memory: 4096,
            parallel: 1
        );
        const string password = "updatetest";

        var oldHash = oldHasher.Hash(password);

        var newHasher = new Argon2PasswordHasher(
            time: 3,
            memory: 8192,
            parallel: 2
        );

        var verified = newHasher.VerifyAndUpdate(oldHash, password, out var isUpdated, out var newHash);

        Assert.True(verified);
        Assert.True(isUpdated);
        Assert.NotEqual(oldHash, newHash);

        Assert.True(Argon2PasswordHasher.TryExtractMetadataValues(newHash, out var values));
        Assert.Equal(8192u, values.MemoryCost);
        Assert.Equal(3u, values.TimeCost);
        Assert.Equal(2u, values.Parallelism);
    }

    [Fact]
    public void VerifyAndUpdate_WithWrongPassword_ReturnsFalse()
    {
        var hasher = new Argon2PasswordHasher();
        const string password = "correctpassword";
        const string wrongPassword = "wrongpassword";

        var hash = hasher.Hash(password);

        var verified = hasher.VerifyAndUpdate(hash, wrongPassword, out var isUpdated, out var newHash);

        Assert.False(verified);
        Assert.False(isUpdated);
        Assert.Equal(hash, newHash);
    }

    [Fact]
    public void VerifyAndUpdate_PreservesSalt_WhenRehashing()
    {
        var oldHasher = new Argon2PasswordHasher(time: 2, memory: 4096, parallel: 1);
        var newHasher = new Argon2PasswordHasher(time: 3, memory: 8192, parallel: 2);
        const string password = "testpassword";

        var oldHash = oldHasher.Hash(password);

        Assert.True(Argon2PasswordHasher.TryExtractMetadataValues(oldHash, out var oldValues));
        Span<byte> oldSalt = stackalloc byte[oldValues.SaltLength];
        Span<byte> oldHashBytes = stackalloc byte[oldValues.HashLength];
        Argon2PasswordHasher.TryExtractMetadata(oldHash, oldSalt, oldHashBytes);

        newHasher.VerifyAndUpdate(oldHash, password, out _, out var newHash);

        Assert.True(Argon2PasswordHasher.TryExtractMetadataValues(newHash, out var newValues));
        Span<byte> newSalt = stackalloc byte[newValues.SaltLength];
        Span<byte> newHashBytes = stackalloc byte[newValues.HashLength];
        Argon2PasswordHasher.TryExtractMetadata(newHash, newSalt, newHashBytes);

        // Salt should be preserved
        Assert.True(oldSalt.SequenceEqual(newSalt));
    }
}

public class HashMetadataValuesTests
{
    [Fact]
    public void HashMetadataValues_IsValueType()
    {
        var values = new HashMetadataValues(
            Argon2Type.Argon2i,
            8192,
            3,
            2,
            2,
            16,
            32
        );

        Assert.True(typeof(HashMetadataValues).IsValueType);
        Assert.Equal(Argon2Type.Argon2i, values.ArgonType);
        Assert.Equal(8192u, values.MemoryCost);
        Assert.Equal(3u, values.TimeCost);
        Assert.Equal(2u, values.Lanes);
        Assert.Equal(2u, values.Parallelism);
        Assert.Equal(16, values.SaltLength);
        Assert.Equal(32, values.HashLength);
    }

    [Fact]
    public void HashMetadataValues_DefaultIsZeroed()
    {
        var values = default(HashMetadataValues);

        Assert.Equal(default, values.ArgonType);
        Assert.Equal(0u, values.MemoryCost);
        Assert.Equal(0u, values.TimeCost);
        Assert.Equal(0u, values.Parallelism);
        Assert.Equal(0, values.SaltLength);
        Assert.Equal(0, values.HashLength);
    }
}

public class Argon2ExceptionTests
{
    [Fact]
    public void Hash_WithInvalidParameters_ThrowsArgon2Exception()
    {
        var hasher = new Argon2PasswordHasher(
            memory: 1, // Too low
            parallel: 255 // Too high for memory
        );

        Assert.Throws<Argon2Exception>(() => hasher.Hash("test"));
    }
}
