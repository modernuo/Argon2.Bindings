using System.Buffers;
using System.Buffers.Text;
using System.Text;

namespace System.Security.Cryptography;

public class Argon2PasswordHasher
{
    public uint TimeCost { get; }

    public uint MemoryCost { get; }

    public uint Parallelism { get; }

    public Argon2Type ArgonType { get; }

    public uint HashLength { get; }

    public uint SaltLength { get; }

    public Encoding StringEncoding { get; }

    public RandomNumberGenerator Rng { get; }

    public int EncodedHashStringSize => (int)(39 + ((HashLength + SaltLength) * 4 + 3) / 3);

    public Argon2PasswordHasher(
        uint time = 3,
        uint memory = 8192,
        uint parallel = 1,
        Argon2Type type = Argon2Type.Argon2i,
        uint hashLength = 32,
        uint saltLength = 16,
        Encoding encoding = null,
        RandomNumberGenerator rng = null
    )
    {
        TimeCost = time;
        MemoryCost = memory;
        Parallelism = parallel;
        ArgonType = type;
        HashLength = hashLength;
        SaltLength = saltLength;
        StringEncoding = encoding ?? Encoding.UTF8;
        Rng = rng ?? RandomNumberGenerator.Create();
    }

    public string Hash(ReadOnlySpan<char> password)
    {
        Span<byte> salt = stackalloc byte[(int)SaltLength];
        Rng.GetBytes(salt);
        return Hash(password, salt);
    }

    public string Hash(ReadOnlySpan<char> password, ReadOnlySpan<byte> salt)
    {
        Span<byte> passwordBytes = stackalloc byte[StringEncoding.GetByteCount(password)];
        StringEncoding.GetBytes(password, passwordBytes);

        Span<byte> hash = stackalloc byte[(int)HashLength];

        return Hash(passwordBytes, salt, hash);
    }

    public string Hash(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, Span<byte> hash)
    {
        Span<byte> encoded = stackalloc byte[EncodedHashStringSize];

        var result = Argon2.Hash(
            TimeCost,
            MemoryCost,
            Parallelism,
            password,
            salt,
            hash,
            encoded,
            (int)ArgonType,
            0x13
        );

        if (result != Argon2Error.OK)
        {
            throw new Argon2Exception("hashing", result);
        }

        var firstNonNull = encoded.LastIndexOfAnyExcept((byte)0);
        if (firstNonNull > -1)
        {
            encoded = encoded[..(firstNonNull + 1)];
        }

        return Encoding.ASCII.GetString(encoded);
    }

    public bool Verify(ReadOnlySpan<char> expectedHash, ReadOnlySpan<char> password)
    {
        Span<byte> expectedHashBytes = stackalloc byte[StringEncoding.GetByteCount(expectedHash) + 1];
        StringEncoding.GetBytes(expectedHash, expectedHashBytes);
        Span<byte> passwordBytes = stackalloc byte[StringEncoding.GetByteCount(password)];
        StringEncoding.GetBytes(password, passwordBytes);
        return Verify(expectedHashBytes, passwordBytes);
    }

    public bool Verify(ReadOnlySpan<byte> expectedHash, ReadOnlySpan<byte> password)
    {
        var result = Argon2.Verify(expectedHash, password, password.Length, (int)ArgonType);

        if (result is Argon2Error.OK or Argon2Error.VERIFY_MISMATCH or Argon2Error.DECODING_FAIL)
        {
            return result == Argon2Error.OK;
        }

        throw new Argon2Exception("verifying", result);
    }

    public bool VerifyAndUpdate(ReadOnlySpan<char> expectedHash, ReadOnlySpan<char> password, out bool isUpdated, out string newFormattedHash)
    {
        var verified = Verify(expectedHash, password);

        if (verified && TryExtractMetadataValues(expectedHash, out var values))
        {
            if (values.MemoryCost != MemoryCost || values.TimeCost != TimeCost || values.Parallelism != Parallelism)
            {
                // Need to rehash - extract salt (TryExtractMetadata will succeed since TryExtractMetadataValues did)
                Span<byte> salt = stackalloc byte[values.SaltLength];
                Span<byte> hash = stackalloc byte[values.HashLength];
                TryExtractMetadata(expectedHash, salt, hash);

                isUpdated = true;
                newFormattedHash = Hash(password, salt);
                return true;
            }
        }

        isUpdated = false;
        newFormattedHash = expectedHash.ToString();
        return verified;
    }

    /// <summary>
    /// Extracts only the numeric metadata values from an Argon2 hash string.
    /// </summary>
    public static bool TryExtractMetadataValues(ReadOnlySpan<char> formattedHash, out HashMetadataValues values)
    {
        values = default;

        // Minimum valid: $argon2i$v=19$m=1,t=1,p=1$AAAA$AAAA
        if (formattedHash.Length < 30 || formattedHash[0] != '$')
        {
            return false;
        }

        // Split by '$' - expecting: "", "argon2{type}", "v={version}", "m=...,t=...,p=...", "{salt}", "{hash}"
        Span<Range> parts = stackalloc Range[7];
        var partCount = formattedHash.Split(parts, '$');

        if (partCount < 6)
        {
            return false;
        }

        // Parse type from parts[1] (e.g., "argon2id")
        Argon2Type type = formattedHash[parts[1]] switch
        {
            "argon2i" => Argon2Type.Argon2i,
            "argon2d" => Argon2Type.Argon2d,
            "argon2id" => Argon2Type.Argon2id,
            _ => (Argon2Type)(-1)
        };

        if ((int)type == -1)
        {
            return false;
        }

        // Parse parameters from parts[3] (e.g., "m=65536,t=3,p=4")
        var paramsStr = formattedHash[parts[3]];
        uint memoryCost = 0, timeCost = 0, parallelism = 0;

        Span<Range> paramParts = stackalloc Range[4];
        var paramCount = paramsStr.Split(paramParts, ',');

        for (var i = 0; i < paramCount; i++)
        {
            var param = paramsStr[paramParts[i]];
            if (param.StartsWith("m=") && uint.TryParse(param[2..], out var m))
            {
                memoryCost = m;
            }
            else if (param.StartsWith("t=") && uint.TryParse(param[2..], out var t))
            {
                timeCost = t;
            }
            else if (param.StartsWith("p=") && uint.TryParse(param[2..], out var p))
            {
                parallelism = p;
            }
        }

        if (memoryCost == 0 || timeCost == 0 || parallelism == 0)
        {
            return false;
        }

        // Calculate decoded lengths for salt and hash
        var saltBase64 = formattedHash[parts[4]];
        var hashBase64 = formattedHash[parts[5]];

        var saltLength = GetBase64DecodedLength(saltBase64.Length);
        var hashLength = GetBase64DecodedLength(hashBase64.Length);

        values = new HashMetadataValues(
            ArgonType: type,
            MemoryCost: memoryCost,
            TimeCost: timeCost,
            Lanes: parallelism,
            Parallelism: parallelism,
            SaltLength: saltLength,
            HashLength: hashLength
        );

        return true;
    }

    /// <summary>
    /// Decodes salt and hash from an Argon2 hash string into caller-provided spans.
    /// Call TryExtractMetadataValues first to get the required span sizes.
    /// </summary>
    public static bool TryExtractMetadata(ReadOnlySpan<char> formattedHash, Span<byte> salt, Span<byte> hash)
    {
        // Split to find salt/hash parts (we know format is valid from TryExtractMetadataValues)
        Span<Range> parts = stackalloc Range[7];
        formattedHash.Split(parts, '$');

        return TryDecodeBase64NoPadding(formattedHash[parts[4]], salt) &&
               TryDecodeBase64NoPadding(formattedHash[parts[5]], hash);
    }

    /// <summary>
    /// Calculates the decoded byte length for a Base64 string without padding.
    /// </summary>
    private static int GetBase64DecodedLength(int base64Length)
    {
        // Base64 encodes 3 bytes into 4 chars
        // Without padding, we need to account for the remainder
        var fullGroups = base64Length / 4;
        var remainder = base64Length % 4;

        var length = fullGroups * 3;
        if (remainder == 2)
        {
            return length + 1;
        }

        if (remainder == 3)
        {
            return length + 2;
        }

        return length;
    }

    /// <summary>
    /// Decodes Base64 without padding into a span.
    /// </summary>
    private static bool TryDecodeBase64NoPadding(ReadOnlySpan<char> base64, Span<byte> output)
    {
        if (base64.IsEmpty)
        {
            return true;
        }

        // Calculate padding needed
        var paddingNeeded = (4 - base64.Length % 4) % 4;

        if (paddingNeeded == 0)
        {
            // No padding needed - decode directly
            // Convert chars to bytes for Base64.DecodeFromUtf8
            Span<byte> base64Bytes = stackalloc byte[base64.Length];
            for (var i = 0; i < base64.Length; i++)
            {
                base64Bytes[i] = (byte)base64[i];
            }

            return Base64.DecodeFromUtf8(base64Bytes, output, out _, out _) == OperationStatus.Done;
        }

        // Need to add padding
        Span<byte> paddedBase64 = stackalloc byte[base64.Length + paddingNeeded];
        for (var i = 0; i < base64.Length; i++)
        {
            paddedBase64[i] = (byte)base64[i];
        }
        paddedBase64[base64.Length..].Fill((byte)'=');

        return Base64.DecodeFromUtf8(paddedBase64, output, out _, out _) == OperationStatus.Done;
    }
}
