using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using SEGURIDAD.DATA.Interfaces;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;


namespace SEGURIDAD.DATA.Repositories
{
    public class TokenRepository : ITokenRepository
    {
        private readonly IConfiguration _config;

        public TokenRepository(IConfiguration config)
        {
            _config = config;
        }

        public string GenerateToken(string correo, int userId)
        {
            var key = Convert.FromBase64String(_config["Jwt:Key"]);

            var creds = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
        new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
        new Claim(ClaimTypes.Email, correo),
        new Claim("usuario", correo)
    };

            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_config.GetValue<int>("Jwt:DurationMinutes")),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }


    }
}
