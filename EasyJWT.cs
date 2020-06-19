using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;

namespace EasyJWT {
    public static class JWT {
        public static ClaimsIdentity ValidateJWT(
            this HttpRequest req, 
            string secretKey, 
            IEnumerable<string> issuers = null, 
            IEnumerable<string> audiences = null) {
            
            if (req.Headers.ContainsKey("Authorization")) {

                var token = req.Headers.FirstOrDefault(
                            h => h.Key == "Authorization")
                            .Value.ToString();

                ClaimsIdentity identity = TokenWorks(token, secretKey, issuers, audiences);

                if (identity == null)
                    throw new UnauthorizedAccessException("Invalid JWT Token!");

                return identity; 
            }
            else 
                throw new UnauthorizedAccessException("Missing Header 'Authorization'!");
        }

        public static ClaimsIdentity GetClaims(
            this HttpRequest req, 
            string secretKey, 
            IEnumerable<string> issuers = null, 
            IEnumerable<string> audiences = null)
        {
            if (req.Headers.ContainsKey("Authorization")) {

                var token = req.Headers.FirstOrDefault(
                            h => h.Key == "Authorization")
                            .Value.ToString();

                ClaimsIdentity identity = TokenWorks(token, secretKey, issuers, audiences);

                if (identity == null)
                    return new ClaimsIdentity();

                return identity; 
            }
            else 
                return new ClaimsIdentity();
        }

        private static ClaimsIdentity TokenWorks(string token, string secretKey, IEnumerable<string> issuers, IEnumerable<string> audiences)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
            var handler = new JwtSecurityTokenHandler();

            var validations = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = key,
                ValidateIssuer = false,
                ValidateAudience = false
            };

            if (issuers != null)
            {
                validations.ValidIssuers = issuers;
                validations.ValidateIssuer = true;
            }

            if (audiences != null)
            {
                validations.ValidAudiences = audiences;
                validations.ValidateAudience = true;
            }

            token = Regex.Replace(token, "[Bb]earer ", string.Empty);

            var identity = handler.ValidateToken(
            token,
            validations,
            out var tokenSecure)
            .Identity as ClaimsIdentity;
            return identity;
        }

        public static string CreateJWTToken(
            string secretKey, 
            DateTime expiration,
            Claim[] claims = null,
            string issuer = null, 
            string audience = null) {           

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));

            var token = new JwtSecurityToken(issuer,
                audience,
                claims,
                expires: expiration);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public static T GetValue <T>(this ClaimsIdentity claims, string name) {
            var first = claims.FindFirst(name);
            if (first == null)
                return default(T);
            return (T)Convert.ChangeType(first.Value, typeof(T));
        }
    }
}