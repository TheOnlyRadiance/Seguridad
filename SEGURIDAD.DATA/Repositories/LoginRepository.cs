using SEGURIDAD.DATA.Interfaces;
using SEGURIDAD.DATA.Modelos;
using System;
using Npgsql;
using Dapper;
using System.Text.RegularExpressions;

namespace SEGURIDAD.DATA.Repositories
{
    public class LoginRepository : ILoginRepository
    {
        private readonly BdSQLConfiguration _config;

        public LoginRepository(BdSQLConfiguration config)
        {
            _config = config;
        }

        // ---------------------------------------------------
        // LOGIN (obtiene usuario por correo)
        // ---------------------------------------------------
        public UsuarioModel Login(string correo)
        {
            if (string.IsNullOrWhiteSpace(correo)) return null;

            using var connection = new NpgsqlConnection(_config.ConnectionString);

            string sql = @"SELECT idusuario, correo, contrasena
                           FROM usuarios
                           WHERE correo = @correo";

            return connection.QueryFirstOrDefault<UsuarioModel>(sql, new { correo });
        }

        // ---------------------------------------------------
        // MÉTODO PRIVADO: VALIDA EL CORREO
        // ---------------------------------------------------
        private bool ValidarCorreo(string correo)
        {
            if (string.IsNullOrWhiteSpace(correo)) return false;

            // Regex: debe tener formato válido y terminar en .com
            var regex = new Regex(@"^[^@\s]+@[^@\s]+\.[cC][oO][mM]$", RegexOptions.IgnoreCase);
            return regex.IsMatch(correo);
        }

        // ---------------------------------------------------
        // REGISTRO (solo inserta — hash debe venir desde AuthController)
        // ---------------------------------------------------
        public bool RegistrarUsuario(string correo, string contrasenaHasheada)
        {
            // Validar correo
            if (!ValidarCorreo(correo))
                throw new ArgumentException("El correo debe ser válido y terminar en .com");

            using var connection = new NpgsqlConnection(_config.ConnectionString);

            string sql = @"
                INSERT INTO usuarios (correo, contrasena)
                VALUES (@correo, @contrasenaHasheada)
                RETURNING idusuario;
            ";

            var id = connection.ExecuteScalar<int?>(sql, new { correo, contrasenaHasheada });

            return id.HasValue;
        }
    }
}
