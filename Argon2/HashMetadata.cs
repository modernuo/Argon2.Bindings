namespace System.Security.Cryptography;

public record HashMetadata(
    Argon2Type ArgonType,
    uint MemoryCost,
    uint TimeCost,
    uint Lanes,
    uint Parallelism,
    byte[] Salt,
    byte[] Hash
)
{
    public string GetBase64Salt() => Convert.ToBase64String(Salt).Replace("=", "");

    public string GetBase64Hash() => Convert.ToBase64String(Hash).Replace("=", "");

    public override string ToString() =>
        $"$argon2{(ArgonType == Argon2Type.Argon2i ? "i" : "d")}$v=19$m={MemoryCost},t={TimeCost},p={Parallelism}${GetBase64Salt()}${GetBase64Hash()}";
}
