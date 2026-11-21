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
