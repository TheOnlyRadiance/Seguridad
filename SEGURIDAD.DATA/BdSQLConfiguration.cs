using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SEGURIDAD.DATA
{
    public class BdSQLConfiguration
    {
        public string ConnectionString { get; set; }

        public BdSQLConfiguration(string connectionString)
        {
            ConnectionString = connectionString;
        }
    }
}
