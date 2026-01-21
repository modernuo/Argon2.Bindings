namespace System.Security.Cryptography;

/// <summary>
/// Value type containing the numeric metadata from an Argon2 hash.
/// </summary>
public readonly record struct HashMetadataValues(
    Argon2Type ArgonType,
    uint MemoryCost,
    uint TimeCost,
    uint Lanes,
    uint Parallelism,
    int SaltLength,
    int HashLength
);
