# .NET Bindings for Argon 2
.NET 10+ bindings for [Argon 2](https://github.com/P-H-C/phc-winner-argon2)

### Installation
Install through NuGet. The package can be found by searching for [Argon2.Bindings](https://www.nuget.org/packages/Argon2.Bindings).
This package only supports x64 and arm64 architectures. Pull requests are welcome to add support for other architectures/operating systems.

### Usage
```csharp
using System.Security.Cryptography;

var hasher = new Argon2PasswordHasher();

string myhash = hasher.Hash("mypassword");
```

## Verification reads the hash, not your configuration (1.20.0)

`Argon2PasswordHasher.Verify` resolves the Argon2 type from the PHC string it is given. An
instance's `ArgonType` configures **hashing** only.

Before 1.20.0, `Verify` passed the instance's own type to native `argon2_verify`, whose
`decode_string` rejects a prefix that disagrees with it and returns `ARGON2_DECODING_FAIL` —
folded into `false`, and so indistinguishable from a wrong password. A hasher configured for
`Argon2id` could not verify an `Argon2i` hash, which made migrating between types impossible for
any consumer storing PHC strings: every existing credential would have appeared invalid.

`VerifyAndUpdate` now also treats a differing type as grounds for a rehash, and generates a fresh
salt when it rehashes instead of reusing the stored one.

If you relied on `Verify` rejecting hashes of another type, pin the type explicitly through
`Argon2.Verify(encoded, pwd, pwdlen, type)`.
