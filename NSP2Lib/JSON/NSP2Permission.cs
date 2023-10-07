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
    public enum NSP2Permission : int
    {
        /// <summary>
        /// Allows the client to read messages sent by other users. System messages will always be visible.
        /// </summary>
        READ = 0,

        /// <summary>
        /// Allows the client to send messages to other users. System messages will always be writeable.
        /// </summary>
        WRITE = 1,

        /// <summary>
        /// Allows the client to view clients, and direct message if the <b>WRITE</b> permission is assigned. If
        /// IP-mask is enabled, only a client with <b>ADMIN</b> permission will be able to view the actual IP addresses.
        /// </summary>
        VIEW_CLIENTS = 2,

        /// <summary>
        /// Allows the client to mute other clients.
        /// </summary>
        MUTE = 3,

        /// <summary>
        /// Allows the client to kick other clients.
        /// </summary>
        KICK = 4,

        /// <summary>
        /// Allows the client to ban other clients.
        /// </summary>
        BAN = 5,

        /// <summary>
        /// Allows the client to turn off the server.
        /// </summary>
        SHUTDOWN = 6,

        /// <summary>
        /// Allows <b>all permissions</b>, and the ability to assign user permissions.
        /// </summary>
        ADMIN = 7
    }

    public class NSP2PermissionList : List<NSP2Permission>
    {
        public enum UpdateMode
        {
            APPEND, REPLACE, REMOVE
        }

        public bool IsAdminOr(NSP2Permission permission)
        {
            return Contains(permission) || Contains(NSP2Permission.ADMIN);
        }

        public bool IsAdmin()
        {
            return Contains(NSP2Permission.ADMIN);
        }

        public void Modify(NSP2PermissionList list, UpdateMode mode=UpdateMode.APPEND)
        {
            switch (mode)
            {
                case UpdateMode.APPEND:
                    {
                        foreach (NSP2Permission perm in list)
                        {
                            if (!Contains(perm))
                                Add(perm);
                        }
                        break;
                    }
                case UpdateMode.REMOVE:
                    {
                        foreach (NSP2Permission perm in list)
                        {
                            if (Contains(perm))
                                Remove(perm);
                        }
                        break;
                    }
                case UpdateMode.REPLACE:
                    {
                        Clear();
                        foreach (NSP2Permission perm in list)
                        {
                            Add(perm);
                        }
                        break;
                    }
                default:
                    break;
            }
        }
    }
}
