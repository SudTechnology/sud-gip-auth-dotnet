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
Console.WriteLine("All SDK tests passed.");
