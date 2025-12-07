using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SEGURIDAD.DTOS.Auth
{
    public class LoginDTO
    {
        [Required(ErrorMessage ="El usuario no ha sido proporcionado.")]
        public string? correo { get; set; }

        [Required(ErrorMessage ="La contraseña no ha sido proporcionada")]
        public string? Contrasena { get; set; }
    }
}
