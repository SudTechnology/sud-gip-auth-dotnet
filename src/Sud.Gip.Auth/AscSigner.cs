using System.Security.Cryptography;
using System.Text;

namespace Sud.Gip.Api;

/// <summary>Calculates App Server Config (ASC) signatures only.</summary>
public static class AscSigner
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    /// <summary>Returns the ASC HMAC-MD5 signature as 32 lowercase hexadecimal characters.</summary>
    /// <param name="appId">Original application ID, encoded as UTF-8.</param>
    /// <param name="appSecret">Original application secret, used as the UTF-8 HMAC key.</param>
    /// <remarks>
    /// Do not append a newline, trim, normalize, or pre-hash either input.
    /// Existing whitespace is preserved. This helper performs no HTTP I/O or caching.
    /// It is separate from RequestSigner (HMAC-SHA1) and JWT authentication;
    /// the JWT HS256 32-byte key minimum does not apply to ASC signing.
    /// </remarks>
    /// <exception cref="ArgumentException">An input is null, empty, or contains invalid Unicode.</exception>
    public static string AscSign(string appId, string appSecret)
    {
        ArgumentException.ThrowIfNullOrEmpty(appId);
        ArgumentException.ThrowIfNullOrEmpty(appSecret);

        // Strict encoding rejects unpaired surrogates instead of silently replacing them.
        byte[] message = StrictUtf8.GetBytes(appId);
        byte[] key = StrictUtf8.GetBytes(appSecret);
        return Convert.ToHexString(HMACMD5.HashData(key, message)).ToLowerInvariant();
    }
}
