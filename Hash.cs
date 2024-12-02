using System.Security.Cryptography;

namespace MrX.Security;

public static class PasswordHash
{
    private const char segmentDelimiter = ':';
    private static readonly int _saltSize = System.Random.Shared.Next(20, 100); // 128 bits
    private static readonly int _keySize = System.Random.Shared.Next(20, 100); // 256 bits
    private static readonly int _iterations = System.Random.Shared.Next(20, 100);
    private static readonly HashAlgorithmName _algorithm = HashAlgorithmName.SHA256;

    public static string Hash(string input)
    {
        var salt = RandomNumberGenerator.GetBytes(_saltSize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            input,
            salt,
            _iterations,
            _algorithm,
            _keySize
        );
        return string.Join(
            segmentDelimiter,
            Convert.ToHexString(hash),
            Convert.ToHexString(salt),
            _iterations,
            _algorithm
        );
    }

    public static bool Verify(string input, string hashString)
    {
        string[] segments = hashString.Split(segmentDelimiter);
        var hash = Convert.FromHexString(segments[0]);
        var salt = Convert.FromHexString(segments[1]);
        var iterations = int.Parse(segments[2]);
        var algorithm = new HashAlgorithmName(segments[3]);
        var inputHash = Rfc2898DeriveBytes.Pbkdf2(
            input,
            salt,
            iterations,
            algorithm,
            hash.Length
        );
        return CryptographicOperations.FixedTimeEquals(inputHash, hash);
    }
}