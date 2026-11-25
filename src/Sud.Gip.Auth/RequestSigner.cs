using System.Security.Cryptography;
using System.Text;

namespace Sud.Gip.Api;

/// <summary>Shared Sud HTTP signing, independent of JWT token authentication.</summary>
public sealed class RequestSigner
{
    private readonly string appId;
    private readonly byte[] secret;

    /// <summary>Use the original application secret unchanged; do not hash or pad it.</summary>
    public RequestSigner(string appId, string appSecret)
    {
        if (!ValidMetadata(appId))
        {
            throw new ArgumentException("Invalid appId.", nameof(appId));
        }
        if (string.IsNullOrWhiteSpace(appSecret))
        {
            throw new ArgumentException("Invalid appSecret.", nameof(appSecret));
        }
        this.appId = appId;
        secret = Encoding.UTF8.GetBytes(appSecret);
    }

    /// <summary>Generate a lowercase hexadecimal HMAC-SHA1 signature.</summary>
    /// <param name="timestamp">Timestamp text, preserved exactly.</param>
    /// <param name="nonce">Nonce text, preserved exactly.</param>
    /// <param name="rawBody">Exact transmitted bytes; use an empty array for no body.</param>
    /// <remarks>
    /// Never deserialize/re-serialize JSON, trim, normalize line endings, decode/re-encode,
    /// or decompress before verification. Every field ends with LF, including the body.
    /// </remarks>
    public string GenerateSignature(string timestamp, string nonce, byte[] rawBody)
    {
        if (!ValidMetadata(timestamp) || !ValidMetadata(nonce))
        {
            throw new ArgumentException("Invalid signature metadata.");
        }
        ArgumentNullException.ThrowIfNull(rawBody);
        using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA1, secret);
        hmac.AppendData(Encoding.UTF8.GetBytes($"{appId}\n{timestamp}\n{nonce}\n"));
        hmac.AppendData(rawBody);
        hmac.AppendData(new byte[] { (byte)'\n' });
        return Convert.ToHexString(hmac.GetHashAndReset()).ToLowerInvariant();
    }

    /// <summary>Validate callback metadata and compare signature bytes in constant time.</summary>
    /// <remarks>No timestamp freshness, replay storage, or URL/method binding is applied.</remarks>
    public bool VerifySignature(string? suppliedAppId, string? timestamp, string? nonce,
        byte[]? rawBody, string? signature)
    {
        if (suppliedAppId != appId || !ValidMetadata(timestamp) || !ValidMetadata(nonce)
            || rawBody is null || signature is null || signature.Length != 40
            || signature.Any(c => !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f')))
        {
            return false;
        }
        var expected = GenerateSignature(timestamp!, nonce!, rawBody);
        return CryptographicOperations.FixedTimeEquals(
            Convert.FromHexString(expected), Convert.FromHexString(signature));
    }

    /// <summary>Build the single-line Authorization value for outgoing Sud API requests.</summary>
    public string GenerateAuthorization(string timestamp, string nonce, byte[] rawBody)
    {
        var signature = GenerateSignature(timestamp, nonce, rawBody);
        return $"Sud-Auth app_id=\"{appId}\",timestamp=\"{timestamp}\",nonce=\"{nonce}\",signature=\"{signature}\"";
    }

    // Reject delimiters/control characters rather than silently changing signed metadata.
    private static bool ValidMetadata(string? value) => !string.IsNullOrEmpty(value)
        && value.All(c => c >= '!' && c <= '~' && c != '"' && c != '\\' && c != ',');
}
