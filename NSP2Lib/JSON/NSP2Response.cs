
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

        public enum StatusMessage
        {
            DEFAULT,
            NO_PERMISSION,
            DECODE_FAIL,
            SUCCESS,
            FAILURE,
            MESSAGE_RECEIVE,
            KICKED,
            BANNED,
            MUTED,
            UNMUTED,
            DISCONNECTED,
            CONNECTED,
            HANDSHAKE_FAIL
        }

        public StatusMessage Result { set; get; } = StatusMessage.DEFAULT;

        public NSP2ConnectedUser? SentBy { set; get; } = null;

        public string Message { set; get; } = "";
    }
}
