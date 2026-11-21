namespace Sud.Gip.Auth;
public record VerificationResult(int Code, string Message);
public static class ErrorCodeEnum
{
    public static readonly VerificationResult SUCCESS = new(0, "成功");
    public static readonly VerificationResult TOKEN_CREATE_FAILED = new(1001, "Token创建失败");
    public static readonly VerificationResult TOKEN_VERIFY_FAILED = new(1002, "Token校验失败");
    public static readonly VerificationResult TOKEN_DECODE_FAILED = new(1003, "Token解析失败");
    public static readonly VerificationResult TOKEN_INVALID = new(1004, "Token非法");
    public static readonly VerificationResult TOKEN_EXPIRED = new(1005, "Token过期");
    public static readonly VerificationResult APP_DATA_INVALID = new(1101, "App数据非法");
    public static readonly VerificationResult UNDEFINE = new(9999, "未知错误");
    public static string? GetMessage(int code) => code switch { 0 => SUCCESS.Message, 1001 => TOKEN_CREATE_FAILED.Message, 1002 => TOKEN_VERIFY_FAILED.Message, 1003 => TOKEN_DECODE_FAILED.Message, 1004 => TOKEN_INVALID.Message, 1005 => TOKEN_EXPIRED.Message, 1101 => APP_DATA_INVALID.Message, 9999 => UNDEFINE.Message, _ => null };
}
public sealed class TokenExpiredException : Exception { public TokenExpiredException() : base("Expired token") {} }
