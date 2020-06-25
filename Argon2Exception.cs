namespace System.Security.Cryptography
{
  public class Argon2Exception : Exception
  {
    public Argon2Exception(string action, Argon2Error error) :
      base($"Error during Argon2 {action}: ({(int)error}) {error}")
    {
    }
  }
}
