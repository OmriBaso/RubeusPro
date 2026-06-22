using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Rubeus.Smb
{
    internal static class SamrRpc
    {
        // MS-SAMR interface UUID: 12345778-1234-ABCD-EF00-0123456789AC v1.0
        public static readonly Guid SAMR_UUID = new Guid("12345778-1234-ABCD-EF00-0123456789AC");
        public const ushort SAMR_VERSION_MAJOR = 1;
        public const ushort SAMR_VERSION_MINOR = 0;

        private const uint SAM_SERVER_CONNECT = 0x00000001;
        private const uint SAM_SERVER_ENUMERATE_DOMAINS = 0x00000010;
        private const uint SAM_SERVER_LOOKUP_DOMAIN = 0x00000020;
        private const uint DOMAIN_LOOKUP = 0x00000200;
        private const uint USER_CHANGE_PASSWORD = 0x00000040;

        private const uint MAXIMUM_ALLOWED = 0x02000000;

        // SamrConnect — opnum 0. impacket's changepasswd uses this (not Connect5).
        // PSAMPR_SERVER_NAME2 is a unique pointer to an opaque 4-byte field that the
        // server ignores; we send a non-null referent id + 4 bytes, then DesiredAccess.
        public static byte[] EncodeSamrConnect(string serverName)
        {
            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms))
            {
                bw.Write((uint)0x000000FF);   // ServerName referent id (non-null marker)
                bw.Write((uint)0);            // ServerName opaque 4-byte data (ignored by server)
                bw.Write(MAXIMUM_ALLOWED);    // DesiredAccess
                return ms.ToArray();
            }
        }

        public static byte[] ParseSamrConnectResponse(byte[] stub)
        {
            // SamrConnectResponse: ServerHandle (SAMPR_HANDLE, 20 bytes) + ErrorCode (4 bytes)
            uint returnValue = BitConverter.ToUInt32(stub, stub.Length - 4);
            if (returnValue != 0)
                throw new Exception(string.Format("[X] SamrConnect failed: NTSTATUS 0x{0:X8}", returnValue));

            byte[] handle = new byte[20];
            Buffer.BlockCopy(stub, 0, handle, 0, 20);
            return handle;
        }

        // SamrLookupDomainInSamServer — opnum 5
        public static byte[] EncodeSamrLookupDomain(byte[] serverHandle, string domainName)
        {
            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms))
            {
                bw.Write(serverHandle); // ServerHandle (20 bytes)
                WriteNdrUnicodeString(bw, domainName);
                return ms.ToArray();
            }
        }

        public static byte[] ParseSamrLookupDomainResponse(byte[] stub)
        {
            uint returnValue = BitConverter.ToUInt32(stub, stub.Length - 4);
            if (returnValue != 0)
                throw new Exception(string.Format("[X] SamrLookupDomainInSamServer failed: NTSTATUS 0x{0:X8}", returnValue));

            // Response: pointer to SID, then SID data, then return value
            // Skip referent ID (4 bytes)
            int offset = 4;

            // Parse RPC_SID: SubAuthorityCount(4) + Revision(1) + SubAuthorityCount(1) + IdentifierAuthority(6) + SubAuthority(4*count)
            uint subAuthCount = BitConverter.ToUInt32(stub, offset);
            offset += 4;
            byte revision = stub[offset]; offset++;
            byte subAuthCount2 = stub[offset]; offset++;

            // IdentifierAuthority (6 bytes, big-endian)
            byte[] identAuth = new byte[6];
            Buffer.BlockCopy(stub, offset, identAuth, 0, 6);
            offset += 6;

            // Build SID bytes: revision(1) + subAuthCount(1) + identAuth(6) + subAuth(4*count)
            int sidLen = 8 + (subAuthCount2 * 4);
            byte[] sid = new byte[sidLen];
            sid[0] = revision;
            sid[1] = subAuthCount2;
            Buffer.BlockCopy(identAuth, 0, sid, 2, 6);
            Buffer.BlockCopy(stub, offset, sid, 8, subAuthCount2 * 4);

            return sid;
        }

        // SamrOpenDomain — opnum 7
        public static byte[] EncodeSamrOpenDomain(byte[] serverHandle, byte[] domainSid)
        {
            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms))
            {
                bw.Write(serverHandle); // ServerHandle (20 bytes)
                bw.Write(MAXIMUM_ALLOWED); // DesiredAccess (matches impacket hSamrOpenDomain default)
                // DomainId (RPC_SID) — count prefix then raw SID
                uint subAuthCount = domainSid[1];
                bw.Write(subAuthCount); // SubAuthorityCount (conformant array max)
                bw.Write(domainSid);
                return ms.ToArray();
            }
        }

        public static byte[] ParseSamrOpenDomainResponse(byte[] stub)
        {
            uint returnValue = BitConverter.ToUInt32(stub, stub.Length - 4);
            if (returnValue != 0)
                throw new Exception(string.Format("[X] SamrOpenDomain failed: NTSTATUS 0x{0:X8}", returnValue));

            byte[] handle = new byte[20];
            Buffer.BlockCopy(stub, 0, handle, 0, 20);
            return handle;
        }

        // SamrLookupNamesInDomain — opnum 17
        public static byte[] EncodeSamrLookupNames(byte[] domainHandle, string username)
        {
            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms))
            {
                bw.Write(domainHandle); // DomainHandle (20 bytes)
                bw.Write((uint)1); // Count
                bw.Write((uint)1000); // MaxCount (conformant array)
                bw.Write((uint)0); // Offset
                bw.Write((uint)1); // ActualCount

                // RPC_UNICODE_STRING element
                byte[] nameBytes = Encoding.Unicode.GetBytes(username);
                bw.Write((ushort)nameBytes.Length);        // Length
                bw.Write((ushort)(nameBytes.Length + 2));  // MaximumLength
                bw.Write((uint)0x00020000);                // Pointer referent id

                // Conformant varying string data
                bw.Write((uint)((nameBytes.Length + 2) / 2)); // MaxCount
                bw.Write((uint)0);                             // Offset
                bw.Write((uint)(nameBytes.Length / 2));        // ActualCount
                bw.Write(nameBytes);

                // Pad to 4-byte boundary
                int pad = (4 - (nameBytes.Length % 4)) % 4;
                if (pad > 0) bw.Write(new byte[pad]);

                return ms.ToArray();
            }
        }

        public static uint ParseSamrLookupNamesResponse(byte[] stub)
        {
            uint returnValue = BitConverter.ToUInt32(stub, stub.Length - 4);
            if (returnValue != 0)
                throw new Exception(string.Format("[X] SamrLookupNamesInDomain failed: NTSTATUS 0x{0:X8}", returnValue));

            // Response: RelativeIds (count + pointer + array data) + Use (count + pointer + array data) + return
            // RelativeIds: Count(4) + pointer(4) -> MaxCount(4) + RID(4)
            // The RID is at: Count(4) + Pointer(4) + MaxCount(4) + RID(4)
            uint rid = BitConverter.ToUInt32(stub, 12);
            return rid;
        }

        // SamrOpenUser — opnum 34
        public static byte[] EncodeSamrOpenUser(byte[] domainHandle, uint userId)
        {
            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms))
            {
                bw.Write(domainHandle); // DomainHandle (20 bytes)
                bw.Write(MAXIMUM_ALLOWED); // DesiredAccess (matches impacket hSamrOpenUser default; USER_CHANGE_PASSWORD alone is insufficient)
                bw.Write(userId); // UserId

                return ms.ToArray();
            }
        }

        public static byte[] ParseSamrOpenUserResponse(byte[] stub)
        {
            uint returnValue = BitConverter.ToUInt32(stub, stub.Length - 4);
            if (returnValue != 0)
                throw new Exception(string.Format("[X] SamrOpenUser failed: NTSTATUS 0x{0:X8}", returnValue));

            byte[] handle = new byte[20];
            Buffer.BlockCopy(stub, 0, handle, 0, 20);
            return handle;
        }

        // The NT OWF hash of the empty-string LM password ("empty LM hash").
        // impacket uses this constant (EMPTY_LM_HASH) for NewLmEncryptedWithNewNt
        // when only an NT hash is supplied for the new password.
        private static readonly byte[] EMPTY_LM_HASH = new byte[]
        {
            0xAA, 0xD3, 0xB4, 0x35, 0xB5, 0x14, 0x04, 0xEE,
            0xAA, 0xD3, 0xB4, 0x35, 0xB5, 0x14, 0x04, 0xEE
        };

        // SamrChangePasswordUser — opnum 38
        // Mirrors impacket's hSamrChangePasswordUser (samr.py): for an NT-hash change it
        // sets LmPresent=0, NtPresent=1, NtCrossEncryptionPresent=0, LmCrossEncryptionPresent=1
        // and sends THREE OWF blocks — OldNtEncryptedWithNewNt, NewNtEncryptedWithOldNt, and
        // NewLmEncryptedWithNewNt (the new LM OWF encrypted with the new NT OWF). The third
        // block is mandatory: the server's NDR field walk trusts LmCrossEncryptionPresent=1
        // and a non-null NewLmEncryptedWithNewNt pointer, so omitting either desyncs the
        // unmarshaller and yields RPC_X_BAD_STUB_DATA (0x6F7). The "new LM" hash is the
        // empty-LM OWF because the account uses an NT-only (LM-disabled) password.
        public static byte[] EncodeSamrChangePasswordUser(byte[] userHandle, byte[] oldNtHash, byte[] newNtHash)
        {
            byte[] oldNtEncryptedWithNewNt = EncryptNtOwfWithNtOwf(oldNtHash, newNtHash);
            byte[] newNtEncryptedWithOldNt = EncryptNtOwfWithNtOwf(newNtHash, oldNtHash);
            byte[] newLmEncryptedWithNewNt = EncryptNtOwfWithNtOwf(EMPTY_LM_HASH, newNtHash);

            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms))
            {
                bw.Write(userHandle); // UserHandle (20 bytes)

                // LmPresent (UCHAR) + 3-byte alignment pad
                bw.Write((byte)0);
                bw.Write(new byte[3]);

                // OldLmEncryptedWithNewLm (unique pointer = NULL)
                bw.Write((uint)0);

                // NewLmEncryptedWithOldLm (unique pointer = NULL)
                bw.Write((uint)0);

                // NtPresent (UCHAR) + pad
                bw.Write((byte)1);
                bw.Write(new byte[3]);

                // OldNtEncryptedWithNewNt — referent ID then INLINE data
                bw.Write((uint)0x00020000);
                bw.Write(oldNtEncryptedWithNewNt);

                // NewNtEncryptedWithOldNt — referent ID then INLINE data
                bw.Write((uint)0x00020004);
                bw.Write(newNtEncryptedWithOldNt);

                // NtCrossEncryptionPresent (UCHAR) + pad
                bw.Write((byte)0);
                bw.Write(new byte[3]);

                // NewNtEncryptedWithNewLm (unique pointer = NULL)
                bw.Write((uint)0);

                // LmCrossEncryptionPresent (UCHAR) + pad
                bw.Write((byte)1);
                bw.Write(new byte[3]);

                // NewLmEncryptedWithNewNt — referent ID then INLINE data
                bw.Write((uint)0x00020008);
                bw.Write(newLmEncryptedWithNewNt);

                byte[] stub = ms.ToArray();
                if (Smb3Crypto.Debug)
                {
                    Console.WriteLine("    [SAMR-CHGPW] oldNtEncWithNewNt={0}", Smb3Crypto.Hex(oldNtEncryptedWithNewNt));
                    Console.WriteLine("    [SAMR-CHGPW] newNtEncWithOldNt={0}", Smb3Crypto.Hex(newNtEncryptedWithOldNt));
                    Console.WriteLine("    [SAMR-CHGPW] stub({0})={1}", stub.Length, Smb3Crypto.Hex(stub));
                }
                return stub;
            }
        }

        public static void ParseSamrChangePasswordUserResponse(byte[] stub)
        {
            uint returnValue = BitConverter.ToUInt32(stub, stub.Length - 4);
            if (returnValue != 0)
            {
                string meaning;
                switch (returnValue)
                {
                    case 0xC000006A: meaning = "STATUS_WRONG_PASSWORD"; break;
                    case 0xC000006C: meaning = "STATUS_PASSWORD_RESTRICTION"; break;
                    case 0xC000006E: meaning = "STATUS_ACCOUNT_RESTRICTION"; break;
                    case 0xC0000022: meaning = "STATUS_ACCESS_DENIED"; break;
                    default: meaning = "Unknown"; break;
                }
                throw new Exception(string.Format("[X] SamrChangePasswordUser failed: NTSTATUS 0x{0:X8} ({1})", returnValue, meaning));
            }
        }

        // SamrCloseHandle — opnum 1
        public static byte[] EncodeSamrCloseHandle(byte[] handle)
        {
            byte[] stub = new byte[20];
            Buffer.BlockCopy(handle, 0, stub, 0, 20);
            return stub;
        }

        // ENCRYPTED_NT_OWF_PASSWORD: DES-ECB encrypt plainHash using keyHash
        // Split keyHash into two 7-byte DES keys, encrypt two 8-byte halves of plainHash
        private static byte[] EncryptNtOwfWithNtOwf(byte[] plainHash, byte[] keyHash)
        {
            byte[] result = new byte[16];

            byte[] key1 = ExpandDesKey(keyHash, 0);
            byte[] key2 = ExpandDesKey(keyHash, 7);

            using (var des = new DESCryptoServiceProvider())
            {
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.None;

                des.Key = key1;
                using (var enc = des.CreateEncryptor())
                    enc.TransformBlock(plainHash, 0, 8, result, 0);

                des.Key = key2;
                using (var enc = des.CreateEncryptor())
                    enc.TransformBlock(plainHash, 8, 8, result, 8);
            }

            return result;
        }

        // Expand 7 bytes to 8-byte DES key with parity bits
        private static byte[] ExpandDesKey(byte[] input, int offset)
        {
            byte[] key = new byte[8];
            key[0] = (byte)(input[offset + 0] >> 1);
            key[1] = (byte)(((input[offset + 0] & 0x01) << 6) | (input[offset + 1] >> 2));
            key[2] = (byte)(((input[offset + 1] & 0x03) << 5) | (input[offset + 2] >> 3));
            key[3] = (byte)(((input[offset + 2] & 0x07) << 4) | (input[offset + 3] >> 4));
            key[4] = (byte)(((input[offset + 3] & 0x0F) << 3) | (input[offset + 4] >> 5));
            key[5] = (byte)(((input[offset + 4] & 0x1F) << 2) | (input[offset + 5] >> 6));
            key[6] = (byte)(((input[offset + 5] & 0x3F) << 1) | (input[offset + 6] >> 7));
            key[7] = (byte)(input[offset + 6] & 0x7F);

            for (int i = 0; i < 8; i++)
                key[i] = (byte)((key[i] << 1) & 0xFE);

            SetDesKeyParity(key);
            return key;
        }

        private static void SetDesKeyParity(byte[] key)
        {
            for (int i = 0; i < key.Length; i++)
            {
                int parity = 0;
                for (int bit = 1; bit < 8; bit++)
                {
                    if ((key[i] & (1 << bit)) != 0) parity++;
                }
                if (parity % 2 == 0)
                    key[i] |= 1;
                else
                    key[i] &= 0xFE;
            }
        }

        // NDR helpers
        private static void WriteNdrUnicodeStringPtr(BinaryWriter bw, string value)
        {
            byte[] bytes = Encoding.Unicode.GetBytes(value);

            // Pointer referent id
            bw.Write((uint)0x00020000);

            // RPC_UNICODE_STRING
            bw.Write((ushort)bytes.Length);        // Length
            bw.Write((ushort)(bytes.Length + 2));   // MaximumLength

            // Pointer to buffer (self-referencing)
            bw.Write((uint)0x00020004);

            // Conformant varying string
            bw.Write((uint)((bytes.Length + 2) / 2)); // MaxCount
            bw.Write((uint)0);                         // Offset
            bw.Write((uint)(bytes.Length / 2));         // ActualCount
            bw.Write(bytes);

            // Pad to 4-byte alignment
            int pad = (4 - (bytes.Length % 4)) % 4;
            if (pad > 0) bw.Write(new byte[pad]);
        }

        private static void WriteNdrUnicodeString(BinaryWriter bw, string value)
        {
            byte[] bytes = Encoding.Unicode.GetBytes(value);

            // RPC_UNICODE_STRING (embedded, not a pointer)
            bw.Write((ushort)bytes.Length);        // Length
            bw.Write((ushort)(bytes.Length + 2));   // MaximumLength

            // Pointer referent id for the buffer
            bw.Write((uint)0x00020000);

            // Conformant varying string data
            bw.Write((uint)((bytes.Length + 2) / 2)); // MaxCount
            bw.Write((uint)0);                         // Offset
            bw.Write((uint)(bytes.Length / 2));         // ActualCount
            bw.Write(bytes);

            int pad = (4 - (bytes.Length % 4)) % 4;
            if (pad > 0) bw.Write(new byte[pad]);
        }
    }
}
