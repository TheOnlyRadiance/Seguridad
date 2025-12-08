using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SEGURIDAD.DATA.Modelos
{
    public class UsuarioModel
    {
        public int IdUsuario { get; set; }

        [Required(ErrorMessage = "El correo es obligatorio")]
        [EmailAddress(ErrorMessage = "Formato de correo inválido")]
        [RegularExpression(@"^[^@\s]+@[^@\s]+\.[^@\s]+$", ErrorMessage = "El correo debe tener formato válido, ejemplo: usuario@dominio.com")]
        public string Correo { get; set; }
        public string Contrasena { get; set; }
    }
}
