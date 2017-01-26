using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Configuration;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Jose;

namespace DiscourseSso.Controllers
{
    [Route("[controller]/[action]")]
    public class AuthController : Controller
    {
        private IConfigurationRoot _config;
        private IDistributedCache _cache;
        private ILogger<AuthController> _logger;

        public AuthController(IDistributedCache cache, IConfigurationRoot config, ILogger<AuthController> logger)
        {
            _logger = logger;
            _config = config;
            _cache = cache;
        }

        public async Task<IActionResult> Login()
        {
            string nonce = Convert.ToBase64String(Guid.NewGuid().ToByteArray()).Replace("=", "").Replace("+", "");
            await _cache.SetStringAsync(nonce, "");
            string returnUrl = $"http://{Request.Host.Value}/Auth/GetToken";

            string payload = $"nonce={nonce}&return_sso_url={returnUrl}";

            string base64Payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(payload));
            string urlEncodedPayload = Uri.EscapeUriString(base64Payload);

            string hexSigniture;
            using (HMACSHA256 hmac = new HMACSHA256(Encoding.ASCII.GetBytes(_config["DiscourseSso:SsoSecret"])))
            {
                byte[] sha256 = hmac.ComputeHash(Encoding.ASCII.GetBytes(base64Payload));
                hexSigniture = BitConverter.ToString(sha256).Replace("-", "").ToLower();
            }

            string redirectTo = $"{_config["DiscourseSso:DiscourseRootUrl"]}/session/sso_provider?sso={urlEncodedPayload}&sig={hexSigniture}";
            return Redirect(redirectTo);

        }

        public async Task<IActionResult> GetToken(string sig, string sso)
        {
            
            byte[] ssoSha256;
            using (HMACSHA256 hmac = new HMACSHA256(Encoding.ASCII.GetBytes(_config["DiscourseSso:SsoSecret"])))
            {
                ssoSha256 = hmac.ComputeHash(Encoding.ASCII.GetBytes(sso));
            }

            byte[] sigBytes = StringToByteArray(sig);

            if (Encoding.ASCII.GetString(ssoSha256) != Encoding.ASCII.GetString(sigBytes))
            {
                _logger.LogDebug($"ssoSha256 != sigBytes");
                return BadRequest("Somehting went wrong.");
            }

            string base64Sso = Uri.UnescapeDataString(Encoding.UTF8.GetString(Convert.FromBase64String(sso)));

            var userInfo = base64Sso.Replace("?", "").Split('&').ToDictionary(x => x.Split('=')[0], x => x.Split('=')[1]);

            if (await _cache.GetStringAsync(userInfo["nonce"]) == null)
                return BadRequest("Nonce not previously registered or has expired.");
            
            string jwt = CreateJwt(userInfo["username"], userInfo);

            return Ok(jwt);
        }

        private static byte[] StringToByteArray(string hex)
        {
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        private string CreateJwt(string sub, Dictionary<string, string> claims = null)
        {
            var payload = new Dictionary<string, object>
            {
                { "sub", sub },
                { "iss", _config["Jwt:Issuer"]},
                { "iat", ToUnixTime(DateTime.Now) },
                { "exp", _config["Jwt:Expiry"] == "" ? ToUnixTime(DateTime.Now.AddDays(30)) : int.Parse(_config["Jwt:Expiry"]) },
                { "aud", _config["Jwt:Audience"] }
            };

            if (claims != null)
            {
                foreach (var kvPair in claims)
                    payload.Add(kvPair.Key, kvPair.Value);
            }

            string token = JWT.Encode(payload,
                Encoding.UTF8.GetBytes(_config["Jwt:SecretKey"]),
                JwsAlgorithm.HS256);

            return token;
        }

        private long ToUnixTime(DateTime dateTime)
        {
            return (int)(dateTime
                .ToUniversalTime()
                .Subtract(new DateTime(1970, 1, 1)))
                .TotalSeconds;
        }
    }
}
