using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Sud.Gip.Api;
namespace Sud.Gip.Auth;

// Implements HS256 token signing and verification with zero clock leeway.
public static class TokenUtils
{
    public const string UID_KEY = "uid", APP_ID_KEY = "app_id";
    internal static byte[] Key(string? secret)
    {
        if (secret is null || Encoding.UTF8.GetByteCount(secret) < 32)
            throw new ArgumentException("HS256 AppSecret must contain at least 32 bytes.", nameof(secret));
        return Encoding.UTF8.GetBytes(secret);
    }
    private static string Encode(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static byte[] Decode(string value)
    {
        var s = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(s.PadRight((s.Length + 3) / 4 * 4, '='));
    }
    public static SdkTokenResponse Token(string appId, string secret, string uid, long expireDuration) =>
        DoCreateToken(secret, new Dictionary<string, object?> { [UID_KEY] = uid, [APP_ID_KEY] = appId }, expireDuration);
    public static SdkTokenResponse DoCreateToken(string secret, IReadOnlyDictionary<string, object?> claims, long expireDuration)
    {
        try
        {
            var expiry = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + expireDuration / 1000m;
            var payload = new Dictionary<string, object?>(claims) { ["exp"] = expiry };
            var input = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." + Encode(JsonSerializer.SerializeToUtf8Bytes(payload));
            return new(input + "." + Encode(HMACSHA256.HashData(Key(secret), Encoding.UTF8.GetBytes(input))), expiry * 1000m);
        }
        catch (Exception ex) when (ex is ArgumentException or JsonException or NotSupportedException or CryptographicException)
        { throw new InvalidOperationException("Token generation failed.", ex); }
    }
    public static VerificationResult Verify(string? token, string? secret)
    {
        if (string.IsNullOrEmpty(token) || token == "0") return ErrorCodeEnum.TOKEN_INVALID;
        if (string.IsNullOrEmpty(secret) || secret == "0") return ErrorCodeEnum.APP_DATA_INVALID;
        try { DoVerify(token, secret); return ErrorCodeEnum.SUCCESS; }
        catch (TokenExpiredException) { return ErrorCodeEnum.TOKEN_EXPIRED; }
        catch (Exception ex) when (ex is ArgumentException or FormatException or JsonException or InvalidOperationException or CryptographicException or OverflowException)
        { return ErrorCodeEnum.TOKEN_VERIFY_FAILED; }
    }
    private static decimal? DateClaim(JsonElement payload, string name)
    {
        if (!payload.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind == JsonValueKind.Number && value.TryGetDecimal(out var number)) return number;
        if (value.ValueKind == JsonValueKind.String && decimal.TryParse(value.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out number)) return number;
        throw new FormatException("Invalid NumericDate: " + name);
    }
    public static JsonElement DoVerify(string token, string secret)
    {
        var parts = token.Split('.');
        if (parts.Length != 3) throw new FormatException("Wrong number of segments");
        using var header = JsonDocument.Parse(Decode(parts[0]));
        using var payload = JsonDocument.Parse(Decode(parts[1]));
        if (header.RootElement.ValueKind != JsonValueKind.Object || !header.RootElement.TryGetProperty("alg", out var alg) || alg.GetString() != "HS256")
            throw new FormatException("Incorrect algorithm");
        var claims = payload.RootElement;
        if (claims.ValueKind != JsonValueKind.Object) throw new FormatException("Payload must be an object");
        var exp = DateClaim(claims, "exp"); var nbf = DateClaim(claims, "nbf"); var iat = DateClaim(claims, "iat");
        var expected = HMACSHA256.HashData(Key(secret), Encoding.UTF8.GetBytes(parts[0] + "." + parts[1]));
        if (!CryptographicOperations.FixedTimeEquals(expected, Decode(parts[2]))) throw new CryptographicException("Signature verification failed");
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (nbf.HasValue && decimal.Floor(nbf.Value) > now || !nbf.HasValue && iat.HasValue && decimal.Floor(iat.Value) > now)
            throw new FormatException("Token is not yet valid");
        if (exp.HasValue && now >= exp.Value) throw new TokenExpiredException();
        return claims.Clone();
    }
    public static string? DoGetValueFromToken(string token, string key, string secret)
    {
        var claims = DoVerify(token, secret);
        return claims.TryGetProperty(key, out var value) && value.ValueKind != JsonValueKind.Null ? value.ToString() : null;
    }
    public static string? GetUID(string token, string secret) => DoGetValueFromToken(token, UID_KEY, secret);
    public static string? GetAppID(string token, string secret) => DoGetValueFromToken(token, APP_ID_KEY, secret);
}
