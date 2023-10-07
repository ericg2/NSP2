using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static NSP2.JSON.NSP2PermissionList;

namespace NSP2.JSON.Message
{
    public class UpdatePermissionTemplate : UserReferenceTemplate
    {
        public UpdateMode Mode { set; get; } = UpdateMode.APPEND;
        public NSP2PermissionList Permissions { set; get; } = new NSP2PermissionList();
    }
}
