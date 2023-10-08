
using NSP2.Client;
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
    public class NSP2Response
    {

        public enum StatusMessage  : int
        {
            DEFAULT = 0,

            CONNECTED = 1,
            MESSAGE_RECEIVE = 2,

            OPERATION_SUCCESS = 3,
            OPERATION_FAILURE = 4,

            MUTED = 5,
            KICKED = 6,
            BANNED = 7,

            UNMUTED = 8,

            DISCONNECTED = 9,

            DISCONNECTED_EVENT = 10,
            CONNECTED_EVENT = 11,
            STATUS_EVENT = 12
        }

        public StatusMessage Result { set; get; } = StatusMessage.MESSAGE_RECEIVE;

        public NSP2ConnectedUser? SentBy { set; get; } = null;

        public string Message { set; get; } = "";
    }
}
