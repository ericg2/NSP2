using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NSP2.JSON.Message
{
    public class UserReferenceTemplate
    {
        public enum UpdateType
        {
            ACCOUNT_NAME, ID_IP
        }

        public UpdateType Type { set; get; } = UpdateType.ID_IP;

        public string Reference { set; get; } = "";
    }
}
