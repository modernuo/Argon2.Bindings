using System.Security.Cryptography;
using Xunit;

namespace Argon2Tests;

public class UnitTest1
{
    [Fact]
    public void TestVerify()
    {
        var hasher = new Argon2PasswordHasher();
        const string password = "123456789";

        var encryptedPassword = hasher.Hash(password);

        var verifyResult = hasher.Verify(encryptedPassword, password);
        Assert.True(verifyResult);
    }
}
