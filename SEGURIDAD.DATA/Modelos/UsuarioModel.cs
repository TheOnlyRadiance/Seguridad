using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SEGURIDAD.DATA.Modelos
{
    public class UsuarioModel
    {
        public int IdUsuario { get; set; }
        public string Correo { get; set; }
        public string Contrasena { get; set; }
    }
}
