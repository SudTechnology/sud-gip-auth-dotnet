# Sud GIP Auth .NET SDK

Standalone .NET 8 SDK for Sud GIP authentication using HS256 JWT tokens. Uses the .NET cryptography and JSON standard libraries, with no external runtime dependencies. Package ID: `Sud.Gip.Auth` (prepared for packaging, not yet published to NuGet).

```csharp
using Sud.Gip.Api;
var auth = new SudGIPAuth("your_app_id", Environment.GetEnvironmentVariable("SUD_APP_SECRET")!);
var code = auth.GetCode("user-001");
var uid = auth.GetUidByCode(code.Code);
if (uid.IsSuccess) {
    var token = auth.GetSSToken(uid.Uid!);
    Console.WriteLine(token.ExpireDate);
}
```

## API and token behavior

Methods and properties use C# PascalCase, such as `GetCode` and `ExpireDate`. JSON response properties use `code`, `token`, `expireDate`, `uid`, `isSuccess`, and `errorCode`. Verification returns `VerificationResult(Code, Message)`. UID and app ID arguments are strings.

- HS256, raw UTF-8 AppSecret, minimum **32 bytes**, no hashing or padding of keys.
- Claims: `uid`, `app_id`, `exp`. No issuer, audience, subject, or token-type claims are added.
- Durations are integer milliseconds. Code defaults to 7,200,000 ms, clamps to at least 1,800,000 ms. SSToken defaults/clamps to 7,200,000 ms. No upper limit.
- Current time is truncated to Unix seconds before adding duration / 1000. Fractional-second expiration is retained; `ExpireDate` is Unix milliseconds (decimal).
- Verification has zero clock leeway, validates HS256 signatures with constant-time comparison, and checks exp/nbf/iat with nbf taking precedence over iat.
- Code and SSToken are interchangeable, `app_id` is not compared against the constructor, and missing exp or uid is not itself rejected. Applications requiring stronger contextual validation must enforce it separately.
- Identical claims/key yield interoperable tokens; JSON escaping may differ, so byte-identical token strings are not promised.
- Constructor rejects short secrets with ArgumentException. Creation failures use InvalidOperationException with the original inner exception. Low-level DoVerify/GetUID/GetAppID throw on invalid tokens; Verify methods return results.
- No tokens, secrets, or decoded claims are logged. No HTTP calls or storage are needed.

| Code | Meaning |
|---|---|
| 0 | Success |
| 1001 | Creation failed (reserved, creation throws) |
| 1002 | Verification failed |
| 1003 | Decoding failed (reserved) |
| 1004 | Empty/invalid token |
| 1005 | Expired token |
| 1101 | Missing app secret (low-level Verify) |
| 9999 | Unknown (reserved) |

Short production keys must be rotated in coordination with the issuer. Do not alter them locally. Tests use public dummy credentials only.

## Build, test, package

```bash
dotnet build Sud.Gip.Auth.sln -c Release
dotnet run --project tests/SdkTests -c Release
dotnet pack src/Sud.Gip.Auth -c Release -o artifacts
```

The test executable exits nonzero on failure. It covers Unicode, expiration/clamps, invalid signatures, algorithms, dates, key lengths and documented validation behavior. This is a library, not an HTTP server. NuGet publication and Git tagging are separate release steps.

CI builds the library, runs the .NET test executable, and creates a NuGet package.

## Rider
Open `Sud.Gip.Auth.sln`. The library is under `src/Sud.Gip.Auth`; the executable
SDK tests are under `tests/SdkTests`. Use the .NET 8 SDK.


## HTTP Request Signing

`RequestSigner` (since 1.1.0) generates outgoing request signatures and validates
incoming callbacks independently from JWT Code/SSToken authentication.

```csharp
using Sud.Gip.Api;
using System.Security.Cryptography;
using System.Text.Json;

var signer = new RequestSigner(appId, appSecret);
var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();
var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
// Serialize once. Send exactly these bytes, not a subsequently re-serialized object.
byte[] rawBody = JsonSerializer.SerializeToUtf8Bytes(new { example = "value" });
string authorization = signer.GenerateAuthorization(timestamp, nonce, rawBody);
// Set the outgoing Authorization header to authorization.
```

The header value is a single line:
`Sud-Auth app_id="...",timestamp="...",nonce="...",signature="..."`.
`GenerateSignature(timestamp, nonce, rawBody)` returns lowercase hexadecimal
HMAC-SHA1 over `appId + "\n" + timestamp + "\n" + nonce + "\n" + rawBody + "\n"`.
Every field ends with LF, including the body. Use an empty byte array for no body.
Metadata must be nonempty printable ASCII without spaces, quotes, backslashes,
or commas. Invalid generation inputs throw `ArgumentException` (including
`ArgumentNullException` for a null body). Use the original secret unchanged.

For callbacks, extract the four `Sud-AppId`, `Sud-Timestamp`, `Sud-Nonce`, and
`Sud-Signature` headers and call:

```csharp
bool valid = signer.VerifySignature(
    receivedAppId, receivedTimestamp, receivedNonce, originalBodyBytes, receivedSignature);
// Reject invalid requests before JSON parsing or business operations.
```

**Always verify the ORIGINAL received bytes. Never deserialize/re-serialize JSON,
trim, normalize whitespace or line endings, decode/re-encode text, or decompress
before verification.** Capture bytes before any request-binding middleware.
Verification returns false for invalid inputs, requires the configured application
ID, and compares decoded digests in constant time. Reject duplicate headers in
the HTTP adapter. Callback signatures do not replace token validation.

This protocol does not bind the method, URL, or query, enforce timestamp freshness,
or store nonces for replay prevention. Apply those service policies separately.
Keep application secrets on trusted servers, not in browsers or mobile clients.


## App Server Config signature (ASC)

Available since **1.2.0**:

```csharp
using Sud.Gip.Api;

string sign = AscSigner.AscSign(appId, appSecret);
```

ASC means **App Server Config**. This helper calculates HMAC-MD5 using the
original UTF-8 application ID as the message and the original UTF-8 secret as
the key, returning **32 lowercase hexadecimal characters**.

**No newline is appended.** Do not trim, normalize, or pre-hash the inputs.
Existing whitespace is preserved. Null, empty, or invalid Unicode inputs throw
`ArgumentException`. The JWT HS256 32-byte key minimum does not apply here.

This helper only calculates the ASC sign. It does not construct URLs, send HTTP
requests, fetch configuration, cache results, or refresh configuration.
`RequestSigner` remains the separate HMAC-SHA1 helper for business API requests
and callbacks; JWT authentication is also separate.
