

using Newtonsoft.Json;
using NSP2.JSON.Message;
using NSP2.Server;
using NSP2.Util;
using System.Dynamic;
/**
*  
* Copyright (c) 2023 Eric Gold (ericg2)
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
namespace NSP2.JSON
{
    public class NSP2Request
    {
        public enum RequestAction
        {
            KEEP_ALIVE,
            SEND_MESSAGE,
            AUTHENTICATE,
            DISCONNECT,
            GET_STATUS,
            UPDATE_PERMISSION,
            KICK,
            BAN,
            MUTE,
            UNMUTE,
            UNBAN
        }

        public RequestAction Type { set; get; } = RequestAction.SEND_MESSAGE;

        public string Message { set; get; } = "";

        public static NSP2Request? ParseAuth(NSP2Account? account)
        {
            NSP2Request req = new NSP2Request()
            {
                Type = RequestAction.AUTHENTICATE
            };

            if (account == null)
                return req;

            if (string.IsNullOrEmpty(account.AccountName) || account.HashedPassword == null)
                return null;

            byte[]? encBytes = NSP2Util.Encrypt(NSP2Util.ENCODING.GetBytes("AUTH"), account.HashedPassword);
            if (encBytes == null)
                return null;

            AuthTemplate auth = new AuthTemplate();
            auth.AccountName = account.AccountName;
            auth.Token = Convert.ToBase64String(encBytes);

            req.Message = JsonConvert.SerializeObject(auth);

            return req;
        }
    }
}
