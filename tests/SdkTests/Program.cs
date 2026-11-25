using Sud.Gip.Api;
using Sud.Gip.Auth;
using System.Text;
using System.Security.Cryptography;
using System.Text.Json;
const string secret = "0123456789abcdef0123456789abcdef";
var auth = new SudGIPAuth("test-app", secret);
void Check(bool value, string name) { if (!value) throw new Exception(name); Console.WriteLine("PASS " + name); }
string Signed(object claims, string algorithm = "HS256") {
    string B(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+','-').Replace('/','_');
    var input = B(JsonSerializer.SerializeToUtf8Bytes(new { typ="JWT", alg=algorithm })) + "." + B(JsonSerializer.SerializeToUtf8Bytes(claims));
    return input + "." + B(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(input)));
}
var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
var code = auth.GetCode("用户/001");
Check(auth.GetUidByCode(code.Code).Uid == "用户/001", "Unicode round trip");
Check(code.ExpireDate >= (now+7200)*1000 && code.ExpireDate <= (now+7202)*1000, "Default expiry");
var min = auth.GetCode("u", -1);
Check(min.ExpireDate >= (now+1800)*1000 && min.ExpireDate <= (now+1802)*1000, "Code minimum");
var ss = auth.GetSSToken("u", 1);
Check(ss.ExpireDate >= (now+7200)*1000, "SSToken minimum");
Check(auth.GetUidBySSToken(code.Code).IsSuccess && auth.GetUidByCode(ss.Token).IsSuccess, "Shared Code/SSToken format");
Check(auth.VerifyCode("invalid").Code == 1002 && auth.VerifyCode("").Code == 1004 && auth.VerifyCode("0").Code == 1004, "Malformed/empty");
Check(TokenUtils.Verify(code.Code, "").Code == 1101, "Missing secret");
Check(new SudGIPAuth("other", new string('x',32)).VerifyCode(code.Code).Code == 1002, "Wrong key");
Check(new SudGIPAuth("other",secret).VerifyCode(code.Code).Code == 0, "App ID is not implicitly compared");
Check(auth.VerifyCode(Signed(new { uid="u", exp=now-1 })).Code == 1005, "Expired");
Check(auth.VerifyCode(Signed(new { uid="u", exp=now+100, nbf=now+100 })).Code == 1002, "Future nbf");
Check(auth.VerifyCode(Signed(new { uid="u", iat=now+100 })).Code == 1002, "Future iat");
Check(auth.VerifyCode(Signed(new { uid="u", exp="bad" })).Code == 1002, "Invalid date");
Check(auth.VerifyCode(Signed(new { uid="u", exp=now+100 },"none")).Code == 1002, "Algorithm rejection");
Check(auth.GetUidByCode(Signed(new { exp=now+100 })).IsSuccess, "Missing UID behavior");
Check(auth.VerifyCode(Signed(new { uid="u" })).Code == 0, "Optional expiry behavior");
Check(TokenUtils.DoVerify(auth.GetCode("u",1800001).Code,secret).GetProperty("exp").GetDecimal()%1 == .001m, "Fractional seconds");
try { new SudGIPAuth("app",new string('x',31)); throw new Exception("Accepted short key"); } catch(ArgumentException) {}
Check(new SudGIPAuth("app",new string('界',11)).GetCode("u").Code.Length>0,"UTF8 key bytes");


// Protocol vectors are independent of this implementation and shared across SDKs.
var signer = new RequestSigner("test-app", "test-secret");
const string timestamp = "1688464949817";
const string nonce = "fixed-nonce";
var vectors = new (byte[] Body, string Signature)[]
{
    (Array.Empty<byte>(), "cb6d64fd0a3dfd78b19da2c7625ec2317b05ef8d"),
    (Encoding.UTF8.GetBytes("{\r\n \"message\":\"用户\", \"n\":1\r\n}"), "0e6f9c9c7ba300bb03ec32277b497b67a62054bc"),
    (new byte[] { 0, 255, 10 }, "d2d001cfd566df480128991a0a124ea6b373727d")
};
foreach (var vector in vectors)
{
    Check(signer.GenerateSignature(timestamp, nonce, vector.Body) == vector.Signature, "Fixed signature vector");
    Check(signer.VerifySignature("test-app", timestamp, nonce, vector.Body, vector.Signature), "Verify original bytes");
    Check(!signer.VerifySignature("other-app", timestamp, nonce, vector.Body, vector.Signature), "Reject wrong app");
    Check(!signer.VerifySignature("test-app", timestamp, nonce, vector.Body.Concat(new byte[] { 32 }).ToArray(), vector.Signature), "Reject modified bytes");
}
Check(signer.GenerateAuthorization(timestamp, nonce, Array.Empty<byte>()) ==
    "Sud-Auth app_id=\"test-app\",timestamp=\"1688464949817\",nonce=\"fixed-nonce\",signature=\"cb6d64fd0a3dfd78b19da2c7625ec2317b05ef8d\"", "Authorization header");
foreach (var invalid in new[] { "", "a b", "a\n", "a\r", "a\\b", "a,b", "a\"b", "用户" })
{
    try
    {
        signer.GenerateAuthorization(invalid, nonce, Array.Empty<byte>());
        throw new Exception("Accepted invalid metadata");
    }
    catch (ArgumentException) { }
    Check(!signer.VerifySignature("test-app", timestamp, invalid, Array.Empty<byte>(), vectors[0].Signature), "Reject invalid metadata");
}
foreach (var invalid in new string?[] { null, "", vectors[0].Signature.ToUpperInvariant(), vectors[0].Signature + "\n", new string('g', 40), new string('0', 40) })
{
    Check(!signer.VerifySignature("test-app", timestamp, nonce, Array.Empty<byte>(), invalid), "Reject invalid signature");
}
Check(!signer.VerifySignature("test-app", timestamp, nonce, null, vectors[0].Signature), "Reject null body");
Check(!new RequestSigner("test-app", "wrong-secret").VerifySignature("test-app", timestamp, nonce, Array.Empty<byte>(), vectors[0].Signature), "Reject wrong secret");
try
{
    signer.GenerateSignature(timestamp, nonce, null!);
    throw new Exception("Accepted null body");
}
catch (ArgumentNullException) { }
try
{
    new RequestSigner("test-app", " ");
    throw new Exception("Accepted empty secret");
}
catch (ArgumentException) { }
// ASC fixtures are independently computed and shared across SDKs.
foreach (var vector in new[]
{
    ("appId", "appSecret", "1a5f39304181dbc2a7fe3c908acf5ef6"),
    ("应用ID", "应用密钥", "95216b1f04d8c9e8788a9ba35b11001d"),
    (" appId ", " appSecret ", "d963b97ffb9d6613b06d7931b6965684"),
    ("appId\n", "appSecret", "5fa35ef2782656fe753e30f2dbbc1dfb")
})
{
    Check(AscSigner.AscSign(vector.Item1, vector.Item2) == vector.Item3, "ASC fixed vector");
}
foreach (var invalid in new string?[] { null, "", "\ud800", "\udfff" })
{
    foreach (bool invalidId in new[] { true, false })
    {
        try
        {
            AscSigner.AscSign(invalidId ? invalid! : "app", invalidId ? "secret" : invalid!);
            throw new Exception("Accepted invalid ASC input");
        }
        catch (ArgumentException) { }
    }
}
Console.WriteLine("All SDK tests passed.");
