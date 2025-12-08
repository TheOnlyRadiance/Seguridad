using Microsoft.IdentityModel.Tokens;
using SEGURIDAD.DATA.Interfaces;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

public class TokenRepository : ITokenRepository
{
    private readonly string _jwtKey;
    private readonly string _jwtIssuer;
    private readonly string _jwtAudience;
    private readonly int _durationMinutes;

    public TokenRepository()
    {
        _jwtKey = Environment.GetEnvironmentVariable("JWT_KEY") ?? throw new Exception("JWT_KEY missing");
        _jwtIssuer = Environment.GetEnvironmentVariable("JWT_ISSUER") ?? throw new Exception("JWT_ISSUER missing");
        _jwtAudience = Environment.GetEnvironmentVariable("JWT_AUDIENCE") ?? throw new Exception("JWT_AUDIENCE missing");
        _durationMinutes = 60; // puedes hacer otra variable de entorno si quieres
    }

    public string GenerateToken(string correo, int userId)
    {
        var keyBytes = Convert.FromBase64String(_jwtKey);

        var creds = new SigningCredentials(new SymmetricSecurityKey(keyBytes), SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
            new Claim(ClaimTypes.Email, correo),
            new Claim("usuario", correo)
        };

        var token = new JwtSecurityToken(
            issuer: _jwtIssuer,
            audience: _jwtAudience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(_durationMinutes),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
