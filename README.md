# .NET Core Bindings for Argon 2
.NET Core 3.1 bindings for [Argon 2](https://github.com/P-H-C/phc-winner-argon2)

### Installation
Install through NuGet. The package can be found by searching for [Argon2.Bindings](https://www.nuget.org/packages/Argon2.Bindings).
This package only supports x64 architecture. Pull requests are welcome to add support for other architectures/operating systems.

### Usage
```csharp
using System.Security.Cryptography;

var hasher = new Argon2PasswordHasher();

string myhash = hasher.Hash("mypassword");
```