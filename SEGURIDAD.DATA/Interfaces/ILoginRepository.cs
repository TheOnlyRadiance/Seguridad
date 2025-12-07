using SEGURIDAD.DATA.Modelos;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SEGURIDAD.DATA.Interfaces
{
    public interface ILoginRepository
    {
        UsuarioModel Login(string correo);
    }
}
