using System.Text.Json.Serialization;
namespace Sud.Gip.Api;
public record SdkTokenResponse([property: JsonPropertyName("token")] string Token, [property: JsonPropertyName("expireDate")] decimal ExpireDate);
public record SudCode([property: JsonPropertyName("code")] string Code, [property: JsonPropertyName("expireDate")] decimal ExpireDate)
{
    public static SudCode CreateBySdkTokenResponse(SdkTokenResponse value) => new(value.Token, value.ExpireDate);
}
public record SudSSToken([property: JsonPropertyName("token")] string Token, [property: JsonPropertyName("expireDate")] decimal ExpireDate)
{
    public static SudSSToken CreateBySdkTokenResponse(SdkTokenResponse value) => new(value.Token, value.ExpireDate);
}
public record SudUid([property: JsonPropertyName("uid")] string? Uid = null, [property: JsonPropertyName("isSuccess")] bool IsSuccess = false, [property: JsonPropertyName("errorCode")] int ErrorCode = 0);
