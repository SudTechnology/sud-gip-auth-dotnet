using Sud.Gip.Auth;
namespace Sud.Gip.Api;
public sealed class SudGIPAuth
{
    public const long DEFAULT_MAX_CODE_EXPIRE_DURATION = 7200000;
    public const long DEFAULT_MIN_CODE_EXPIRE_DURATION = 1800000;
    public const long DEFAULT_MIN_SSTOKEN_EXPIRE_DURATION = 7200000;
    private readonly string appId, appSecret;
    public SudGIPAuth(string appId, string appSecret)
    {
        TokenUtils.Key(appSecret);
        this.appId = appId; this.appSecret = appSecret;
    }
    public SudCode GetCode(string uid, long? expireDuration = null) => SudCode.CreateBySdkTokenResponse(
        TokenUtils.Token(appId, appSecret, uid, Math.Max(expireDuration ?? DEFAULT_MAX_CODE_EXPIRE_DURATION, DEFAULT_MIN_CODE_EXPIRE_DURATION)));
    public SudSSToken GetSSToken(string uid, long? expireDuration = null) => SudSSToken.CreateBySdkTokenResponse(
        TokenUtils.Token(appId, appSecret, uid, Math.Max(expireDuration ?? DEFAULT_MIN_SSTOKEN_EXPIRE_DURATION, DEFAULT_MIN_SSTOKEN_EXPIRE_DURATION)));
    public VerificationResult VerifyCode(string? code) => TokenUtils.Verify(code, appSecret);
    public VerificationResult VerifySSToken(string? token) => TokenUtils.Verify(token, appSecret);
    public SudUid GetUidByCode(string code) => GetSdkUidResponse(code);
    public SudUid GetUidBySSToken(string token) => GetSdkUidResponse(token);
    private SudUid GetSdkUidResponse(string token)
    {
        var result = VerifySSToken(token);
        return result.Code == 0 ? new(TokenUtils.GetUID(token, appSecret), true) : new(null, false, result.Code);
    }
}
