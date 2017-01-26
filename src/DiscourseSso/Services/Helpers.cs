using Jose;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DiscourseSso.Services
{
    public class Helpers
    {
        private IConfigurationRoot _config;
        public Helpers(IConfigurationRoot config)
        {
            _config = config;
        }

        public string CreateJwt(string sub, Dictionary<string, string> claims = null)
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
