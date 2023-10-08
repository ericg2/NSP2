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

using Konscious.Security.Cryptography;
using Newtonsoft.Json;
using NSP2.JSON;
using System.IO.Compression;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace NSP2.Util
{
    public class NSP2Util
    {
        public readonly static byte[] SALT_PREFIX = new byte[] { 4, 5, 3, 8 };
        public readonly static byte[] LOOPBACK_SUFFIX = new byte[] { 7, 1, 6, 9 };

        public readonly static Encoding ENCODING = new UTF8Encoding();

        /// <summary>
        /// Hashes a specific password with the Argon2 algorithm. Defaults to 65536K, 4 iterations, and
        /// an 8-bit hash minimum, in order to have room for the integrated salt.
        /// </summary>
        /// <param name="password">The plaintext password to hash</param>
        /// <param name="salt">Output salt parameter</param>
        /// <returns>A 64-bit ByteArray containing the Hash and Salt, or null if an error occurred.</returns>
        public static byte[]? HashPassword(string password, out byte[] salt)
        {
            salt = ENCODING.GetBytes(GenerateRandomString(16));
            return HashPassword(password, salt);
        }

        /// <summary>
        /// Hashes a specific password with the Argon2 algorithm. Defaults to 65536K, 4 iterations, and
        /// an 8-bit hash minimum, in order to have room for the integrated salt.
        /// </summary>
        /// <param name="password">The plaintext password to hash</param>
        /// <param name="salt">The salt ByteArray</param>
        /// <returns>A 64-bit ByteArray containing the Hash and Salt, or null if an error occurred.</returns>
        public static byte[]? HashPassword(string password, byte[] salt)
        {
            if (string.IsNullOrEmpty(password))
                return null;
            if (salt.Length >= 24)
                return null;
            try
            {
                List<byte> hashList = new Argon2id(ENCODING.GetBytes(password))
                {
                    Salt = salt,
                    DegreeOfParallelism = Environment.ProcessorCount * 2,
                    Iterations = 4,
                    MemorySize = 65536
                }.GetBytes(32 - (salt.Length + SALT_PREFIX.Length)).ToList();

                hashList.InsertRange(0, salt);
                hashList.InsertRange(salt.Length, SALT_PREFIX);

                return hashList.ToArray();
            } catch (Exception)
            { }
            return null;
        }

        /// <summary>
        /// Tests if two ByteArrays are the same length, and contain equal values.
        /// </summary>
        /// <param name="a1">Byte Array #1</param>
        /// <param name="a2">Byte Array #2</param>
        /// <returns>The equality of the input arrays.</returns>
        public static bool ByteArraysEqual(ReadOnlySpan<byte> a1, ReadOnlySpan<byte> a2)
        {
            return a1.SequenceEqual(a2);
        }

        /// <summary>
        /// Splits a ByteArray by a delimiter, similar to <see cref="string.Split(char[]?)"/>
        /// </summary>
        /// <param name="source">The input ByteArray to process</param>
        /// <param name="separator">The delimiter ByteArray to split by.</param>
        /// <returns>A two-dimensional ByteArray, split by the Delimiter.</returns>
        public static byte[][] SeperateBytes(byte[] source, byte[] separator)
        {
            var parts = new List<byte[]>();
            var index = 0;
            byte[] part;
            for (int i = 0; i < source.Length; ++i)
            {
                bool equal = true;
                for (int j = i; j < separator.Length; ++j)
                {
                    if (index + j >= source.Length || source[index + j] != separator[j])
                    {
                        equal = false;
                        break;
                    }
                }                
                if (equal)
                {
                    part = new byte[i - index];
                    Array.Copy(source, index, part, 0, part.Length);
                    parts.Add(part);
                    index = i + separator.Length;
                    i += separator.Length - 1;
                }
            }
            part = new byte[source.Length - index];
            Array.Copy(source, index, part, 0, part.Length);
            parts.Add(part);
            return parts.ToArray();
        }

        /// <summary>
        /// Validates a Password hashed by the <see cref="HashPassword(string, byte[])"/> 
        /// method. This is <b>NOT</b> compatible with other Hash Types, due to the specialized
        /// algorithm, and the salt being encoded into the 64-bit hash.
        /// </summary>
        /// <param name="password">The plaintext password to check</param>
        /// <param name="hash">The hash to verify</param>
        /// <returns>The validity of the password.</returns>
        public static bool ValidatePassword(string password, byte[] hash)
        {
            byte[][] spl = SeperateBytes(hash, SALT_PREFIX);
            if (spl.Length <= 1)
                return false;
            return ByteArraysEqual(hash, HashPassword(password, spl[0]));
        }

        /// <summary>
        /// Generate a random alphanumeric string with a specified length.
        /// </summary>
        /// <param name="length">The length to generate</param>
        /// <returns>The randomly generated string</returns>
        public static string GenerateRandomString(int length)
        {
            string charset = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm";
            Random rand = new Random();
            StringBuilder sb = new StringBuilder();
            for (int i=0; i<length; i++)
            {
                sb.Append(charset[rand.Next(charset.Length)]);
            }
            return sb.ToString();
        }

        /// <summary>
        /// Decrypts ciphertext with a password-hash ByteArray.
        /// </summary>
        /// <param name="cipher">The cipher to decrypt</param>
        /// <param name="passHash">The password-hash to use for decryption</param>
        /// <returns>The decrypted text.</returns>
        public static byte[]? Decrypt(byte[] cipher, byte[] passHash)
        {
            try
            {
                using (Aes aes = Aes.Create())
                {
                    aes.KeySize = 256;
                    aes.BlockSize = 128;
                    aes.Key = passHash;

                    List<byte> cipherList = cipher.ToList();

                    aes.IV = cipherList.Take(16).ToArray();
                    cipherList.RemoveRange(0, 16);

                    byte[] data = cipherList.ToArray();

                    using (ICryptoTransform transform = aes.CreateDecryptor())
                    {
                        return transform.TransformFinalBlock(data, 0, data.Length);
                    }
                }
            }
            catch (Exception)
            {
                return null;
            }
        }

        /// <summary>
        /// Encrypts plaintext with a password-hash ByteArray.
        /// </summary>
        /// <param name="plaintext">The plaintext to encrypt</param>
        /// <param name="passHash">The password-hash to use for encryption</param>
        /// <returns>The encrypted ByteArray.</returns>
        public static byte[]? Encrypt(byte[] plaintext, byte[] passHash)
        {
            try
            {
                using (Aes aes = Aes.Create())
                {
                    aes.KeySize = 256;
                    aes.BlockSize = 128;
                    aes.Key = passHash;
                    aes.GenerateIV();

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    {
                        List<byte> encrypted = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length).ToList();

                        encrypted.InsertRange(0, aes.IV);

                        aes.Dispose();
                        encryptor.Dispose();

                        return encrypted.ToArray();
                    }
                }
            }
            catch (Exception)
            {
                return null;
            }         
        }

        public static T? ReceivePacket<T>(TcpClient sock, out bool isLoopBack, byte[]? passHash=null, bool useCompression=true, TimeSpan? timeout=null)
        {
            byte[]? packet = ReceivePacketBytes(sock, out isLoopBack, passHash, useCompression, timeout);
            if (packet == null)
                return default;
            return JsonConvert.DeserializeObject<T>(ENCODING.GetString(packet));
        }

        public static byte[]? ReceivePacketBytes(TcpClient sock, out bool isLoopBack, byte[]? passHash = null, bool useCompression = true, TimeSpan? timeout = null)
        {
            DateTime? expire = null;
            byte[]? req = null;
            isLoopBack = false;
            int oldTimeout = sock.ReceiveTimeout;

            if (timeout != null)
            {
                expire = DateTime.Now + timeout;
            }

            while ((expire == null ? true : DateTime.Now < expire) && sock.Connected)
            {
                // Attempt to read the first 4 bytes and determine the buffer.
                try
                {
                    NetworkStream stream = sock.GetStream();

                    if (timeout.HasValue)
                    {
                        TimeSpan ts = timeout.GetValueOrDefault();
                        if (!IsDefault<TimeSpan>(ts))
                            sock.ReceiveTimeout = Convert.ToInt32(ts.TotalMilliseconds);
                    }

                    byte[] lenBuffer = new byte[4];
                    stream.Read(lenBuffer, 0, lenBuffer.Length);

                    int length = BitConverter.ToInt32(lenBuffer, 0);

                    byte[] dataBuffer = new byte[length];
                    stream.Read(dataBuffer, 0, dataBuffer.Length);

                    List<byte> combo = new List<byte>();
                    combo.AddRange(lenBuffer);
                    combo.AddRange(dataBuffer);

                    req = DecodePacket(combo.ToArray(), out isLoopBack, passHash, useCompression);
                } catch (Exception ex)
                {
                    if (ex.InnerException is SocketException || ex.InnerException is ObjectDisposedException)
                        // The socket has ended connection.
                        return null;
                    else
                        continue;
                }
                if (req == null)
                    continue;
                else
                    return req;
            }

            sock.ReceiveTimeout = oldTimeout;
            return req;
        }


        public static bool IsPacketLoopBack(byte[] packetBytes)
        {
            List<byte> byteList = packetBytes.ToList();
            return ByteArraysEqual(byteList.TakeLast(4).ToArray(), LOOPBACK_SUFFIX);
        }


        public static bool IsDefault<T>(object value)
        {
            return object.Equals(value, default(T));
        }

        /// <summary>
        /// Attempts to decode a packet, with optional password-hash and compression.
        /// </summary>
        /// <param name="packetBytes">The packet ByteArray to decode.</param>
        /// <param name="passHash">The password hash ByteArray.</param>
        /// <param name="useCompression">If de-compression should be used.</param>
        /// <returns>A decoded packet, or null if an error occurred.</returns>
        public static byte[]? DecodePacket(byte[] packetBytes, out bool isLoopBack, byte[]? passHash=null, bool useCompression=true)
        {
            isLoopBack = false;

            if (packetBytes == null || packetBytes.Length == 0)
                return default;
            try
            {
                List<byte> byteList = packetBytes.ToList();

                if (ByteArraysEqual(byteList.TakeLast(4).ToArray(), LOOPBACK_SUFFIX))
                {
                    isLoopBack = true;
                    byteList.RemoveRange(byteList.Count - 4, 4);
                }

                int len = BitConverter.ToInt32(byteList.Take(4).ToArray(), 0);

                if (packetBytes.Length - 4 != len)
                    return default; // corrupt packet.

                byteList.RemoveRange(0, 4);

                packetBytes = byteList.ToArray();

                if (passHash != null && passHash.Length > 0)
                {
                    byte[]? dec = Decrypt(packetBytes, passHash);
                    if (dec == null)
                        return default;
                    packetBytes = dec;
                }
                if (useCompression)
                {
                    using (var compressedStream = new MemoryStream(packetBytes))
                    using (var zipStream = new GZipStream(compressedStream, CompressionMode.Decompress))
                    using (var resultStream = new MemoryStream())
                    {
                        zipStream.CopyTo(resultStream);
                        packetBytes = resultStream.ToArray();
                    }
                }

                return packetBytes;
            }
            catch (Exception)
            {
                return default;
            }
        }

        /// <summary>
        /// Attempts to decode a packet, with optional password-hash and compression.
        /// </summary>
        /// <param name="packetBytes">The packet ByteArray to decode.</param>
        /// <param name="passHash">The password hash ByteArray.</param>
        /// <param name="useCompression">If de-compression should be used.</param>
        /// <returns>A decoded packet object, or null if an error occurred.</returns>
        public static T? DecodePacket<T>(byte[] packetBytes, out bool isLoopBack, byte[]? passHash = null, bool useCompression = true)
        {
            byte[]? packet = DecodePacket(packetBytes, out isLoopBack, passHash, useCompression);
            if (packet == null)
                return default;

            return JsonConvert.DeserializeObject<T>(ENCODING.GetString(packet));
        }

        public static T? DecodePacket<T>(byte[] packetBytes, byte[]? passHash = null, bool useCompression = true)
        {
            return DecodePacket<T>(packetBytes, out _, passHash, useCompression);
        }

        public static bool IsID(string reference)
        {
            return reference.Substring(0, 2).ToUpper().Equals("ID");
        }

        /// <summary>
        /// Generates a packet from an object, with optional password-hash compression.
        /// </summary>
        /// <param name="obj">The object to encode.</param>
        /// <param name="passHash">The password hash ByteArray.</param>
        /// <param name="useCompression">If compression should be used.</param>
        /// <param name="isLoopBack">If the packet is a "loopback", and not intended to be re-broadcasted.</param>
        /// <returns>An encoded packet, or null if an error occurred.</returns>
        public static byte[]? GeneratePacket<T>(T obj, byte[]? passHash=null, bool useCompression=false, bool isLoopBack=false)
        {
            try
            {
                byte[] objBytes = ENCODING.GetBytes(JsonConvert.SerializeObject(obj));

                if (useCompression)
                {
                    using (var compressedStream = new MemoryStream())
                    using (var zipStream = new GZipStream(compressedStream, CompressionMode.Compress))
                    {
                        zipStream.Write(objBytes, 0, objBytes.Length);
                        zipStream.Close();
                        objBytes = compressedStream.ToArray();
                    }
                }

                if (passHash != null && passHash.Length > 0)
                {
                    byte[]? enc = Encrypt(objBytes, passHash);
                    if (enc == null)
                        return null;
                    objBytes = enc;
                }


                List<byte> objBytesList = objBytes.ToList();

                // Add the size to the beginning.
                objBytesList.InsertRange(0, BitConverter.GetBytes(objBytes.Length));

                if (isLoopBack)
                    objBytesList.AddRange(LOOPBACK_SUFFIX);

                Console.WriteLine("Generated packet with length " + objBytesList.Count);
                return objBytesList.ToArray();
            }
            catch (Exception)
            {
                return null;
            }
        }
    }
}
