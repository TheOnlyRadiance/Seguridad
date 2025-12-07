using SEGURIDAD.DATA.Interfaces;
using SEGURIDAD.DATA.Modelos;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Npgsql;
using Dapper;


namespace SEGURIDAD.DATA.Repositories
{
    public class LoginRepository : ILoginRepository
    {
        private readonly BdSQLConfiguration _config;

        public LoginRepository(BdSQLConfiguration config)
        {
            _config = config;
        }

        public UsuarioModel Login(string correo)
        {
            using var connection = new NpgsqlConnection(_config.ConnectionString);

            string sql = @"SELECT idusuario, correo, contrasena 
                       FROM usuarios 
                       WHERE correo = @correo";

            return connection.QueryFirstOrDefault<UsuarioModel>(sql, new { correo });
        }
    }
}
