using System.Runtime.InteropServices;
using System.Text;

namespace System.Security.Cryptography
{
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
      Rng = rng ?? new RNGCryptoServiceProvider();
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
      
      var result = Argon2.Library.Hash(
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
        throw new Argon2Exception("hashing", result);

      var firstNonNull = encoded.Length - 2;
      while (encoded[firstNonNull] == 0)
        firstNonNull--;

      return Encoding.ASCII.GetString(encoded.Slice(0, firstNonNull + 1));
    }

    public bool Verify(ReadOnlySpan<char> expectedHash, ReadOnlySpan<char> password)
    {
      Span<byte> expectedHashBytes = stackalloc byte[StringEncoding.GetByteCount(expectedHash)];
      StringEncoding.GetBytes(expectedHash, expectedHashBytes);
      Span<byte> passwordBytes = stackalloc byte[StringEncoding.GetByteCount(password)];
      StringEncoding.GetBytes(password, passwordBytes);
      return Verify(expectedHashBytes, passwordBytes);
    }

    public bool Verify(ReadOnlySpan<byte> expectedHash, ReadOnlySpan<byte> password)
    {
      var result = Argon2.Library.Verify(expectedHash, password, password.Length, (int)ArgonType);

      if (result == Argon2Error.OK || result == Argon2Error.VERIFY_MISMATCH || result == Argon2Error.DECODING_FAIL)
        return result == Argon2Error.OK;

      throw new Argon2Exception("verifying", result);
    }

    public bool VerifyAndUpdate(ReadOnlySpan<char> expectedHash, ReadOnlySpan<char> password, out bool isUpdated, out string newFormattedHash)
    {
      bool verified = Verify(expectedHash, password);

      if (verified)
      {
        var hashMetadata = ExtractMetadata(expectedHash);

        if (hashMetadata.MemoryCost != MemoryCost || hashMetadata.TimeCost != TimeCost || hashMetadata.Parallelism != Parallelism)
        {
          isUpdated = true;
          byte[] salt = hashMetadata.Salt;
          newFormattedHash = Hash(password, salt);
          return true;
        }
      }

      isUpdated = false;
      newFormattedHash = expectedHash.ToString();
      return verified;
    }
    
    public static HashMetadata ExtractMetadata(ReadOnlySpan<char> formattedHash)
    {
      var context = new Argon2Context
      {
        Out = Marshal.AllocHGlobal(formattedHash.Length),  // ensure the space to hold the hash is long enough
        OutLen = (uint)formattedHash.Length,
        Pwd = Marshal.AllocHGlobal(1),
        PwdLen = 1,
        Salt = Marshal.AllocHGlobal(formattedHash.Length),  // ensure the space to hold the salt is long enough
        SaltLen = (uint)formattedHash.Length,
        Secret = Marshal.AllocHGlobal(1),
        SecretLen = 1,
        AssocData = Marshal.AllocHGlobal(1),
        AssocDataLen = 1,
        TimeCost = 0,
        MemoryCost = 0,
        Lanes = 0,
        Threads = 0
      };

      try
      {
        var type = formattedHash.StartsWith("$argon2i") ? Argon2Type.Argon2i : Argon2Type.Argon2d;
        formattedHash = $"{formattedHash.ToString()}\0";

        Span<byte> bytes = stackalloc byte[formattedHash.Length];
        Encoding.ASCII.GetBytes(formattedHash, bytes);

        var result = Argon2.Library.Decode(context, bytes, (int)type);

        if (result != Argon2Error.OK)
          return null;

        var salt = new byte[context.SaltLen];
        var hash = new byte[context.OutLen];
        Marshal.Copy(context.Salt, salt, 0, salt.Length);
        Marshal.Copy(context.Out, hash, 0, hash.Length);

        return new HashMetadata
        {
          ArgonType = type,
          MemoryCost = context.MemoryCost,
          TimeCost = context.TimeCost,
          Parallelism = context.Threads,
          Salt = salt,
          Hash = hash
        };
      }
      finally
      {
        Marshal.FreeHGlobal(context.Out);
        Marshal.FreeHGlobal(context.Pwd);
        Marshal.FreeHGlobal(context.Salt);
        Marshal.FreeHGlobal(context.Secret);
        Marshal.FreeHGlobal(context.AssocData);
      }
    }
  }
}
