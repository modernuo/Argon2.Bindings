# Argon 2 for .NET Core
.NET Core bindings for [Argon 2](https://github.com/P-H-C/phc-winner-argon2)

### Usage

```csharp
using System.Security.Cryptography;

var hasher = new Argon2PasswordHasher();

string myhash = hasher.Hash("mypassword");
```