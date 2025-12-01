using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SEGURIDAD.DATA.Interfaces
{
    public interface ICryptoService
    {
        string EncryptToBase64(string plainText);
        string DecryptFromBase64(string cipherTextBase64);
    }
}
