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

using Newtonsoft.Json;
using NSP2.JSON;
using NSP2.Util;

namespace NSP2.Server
{
    public class NSP2Account
    {
        public string AccountName { set; get; } = "";

        [JsonIgnore]
        public string Password { set; get; } = "";

        public byte[]? HashedPassword
        {
            get
            {
                if (string.IsNullOrEmpty(Password))
                    return null;
                return NSP2Util.HashPassword(Password, out _);
            }
        }

        public NSP2PermissionList Permissions { set; get; } = new NSP2PermissionList();

        public DateTime CreationDate { set; get; } = DateTime.Now;

        public DateTime LastConnected { set; get; } = new DateTime();

        public bool IsBanned { set; get; } = false;
    }
}
