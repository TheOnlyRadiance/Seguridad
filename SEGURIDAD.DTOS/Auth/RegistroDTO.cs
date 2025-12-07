using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SEGURIDAD.DTOS.Auth
{
    public class RegistroDTO
    {
        [Required(ErrorMessage = "El correo es obligatorio")]
        public string Correo { get; set; }

        [Required(ErrorMessage = "La contraseña es obligatoria")]
        public string Contrasena { get; set; }
    }
}
