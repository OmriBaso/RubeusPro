using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Rubeus.Smb
{
    internal class Smb2Client : IDisposable
    {
        private TcpClient _tcp;
        private NetworkStream _stream;
        private ulong _messageId;
        private ulong _sessionId;
        private uint _treeId;
        private byte[] _fileId;
        private byte[] _signingKey;

        // SMB 3.0 state. When the DC selects dialect 0x0300 we derive AES keys from the
        // NTLM session key and switch the transport into AES-128-CCM encryption — required
        // for SAMR password operations on patched DCs (CVE-2021-33757).
        private ushort _dialect;
        private byte[] _encryptionKey;   // client -> server
        private byte[] _decryptionKey;   // server -> client
        private byte[] _smb3SigningKey;
        private bool _encrypt;

        private const int SMB2_HEADER_SIZE = 64;
        private const ushort SMB2_DIALECT_30 = 0x0300;
        private const uint SMB2_GLOBAL_CAP_ENCRYPTION = 0x00000040;

        public ushort Dialect { get { return _dialect; } }

        // SMB2 Commands
        private const ushort SMB2_NEGOTIATE = 0x0000;
        private const ushort SMB2_SESSION_SETUP = 0x0001;
        private const ushort SMB2_LOGOFF = 0x0002;
        private const ushort SMB2_TREE_CONNECT = 0x0003;
        private const ushort SMB2_TREE_DISCONNECT = 0x0004;
        private const ushort SMB2_CREATE = 0x0005;
        private const ushort SMB2_CLOSE = 0x0006;
        private const ushort SMB2_WRITE = 0x0009;
        private const ushort SMB2_READ = 0x0008;
        private const ushort SMB2_IOCTL = 0x000B;

        // STATUS codes
        private const uint STATUS_SUCCESS = 0x00000000;
        private const uint STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016;
        private const uint STATUS_LOGON_FAILURE = 0xC000006D;

        public void Connect(string host, int port = 445)
        {
            _tcp = new TcpClient();
            _tcp.Client.Ttl = 128;
            _tcp.Connect(host, port);
            _stream = _tcp.GetStream();
            // Fail fast instead of hanging forever if the server silently drops a
            // request (e.g. a signature it rejected) and never replies.
            _stream.ReadTimeout = 15000;
            _messageId = 0;
        }

        public void Negotiate()
        {
            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms))
            {
                bw.Write((ushort)36);  // StructureSize
                bw.Write((ushort)3);   // DialectCount
                bw.Write((ushort)0x01); // SecurityMode (SIGNING_ENABLED)
                bw.Write((ushort)0);   // Reserved
                bw.Write(SMB2_GLOBAL_CAP_ENCRYPTION); // Capabilities (advertise encryption)
                bw.Write(Guid.NewGuid().ToByteArray()); // ClientGuid (16 bytes)
                bw.Write((uint)0);     // NegotiateContextOffset
                bw.Write((ushort)0);   // NegotiateContextCount
                bw.Write((ushort)0);   // Reserved2
                bw.Write((ushort)0x0202); // Dialect SMB 2.002
                bw.Write((ushort)0x0210); // Dialect SMB 2.1
                bw.Write((ushort)0x0300); // Dialect SMB 3.0

                byte[] response = SendReceive(SMB2_NEGOTIATE, ms.ToArray());
                uint status = GetStatus(response);
                if (status != STATUS_SUCCESS)
                    throw new Exception(string.Format("[X] SMB2 Negotiate failed with status 0x{0:X8}", status));

                // DialectRevision is the first field of the negotiate response body.
                _dialect = BitConverter.ToUInt16(response, SMB2_HEADER_SIZE + 4);
                if (_debug) Console.WriteLine("    [NEG] DC selected dialect 0x{0:X4}", _dialect);
            }
        }

        public uint LastSessionSetupStatus { get; private set; }

        public void EnableSigning(byte[] sessionKey)
        {
            _signingKey = sessionKey;

            // SMB 3.0: derive AES signing/encryption/decryption keys from the NTLM session
            // key via the SP800-108 counter KDF (MS-SMB2 3.1.4.2). The label/context strings
            // are null-terminated ASCII; the trailing \0 is part of the KDF input. Once keys
            // exist we switch the transport into AES-128-CCM encrypted mode.
            if (_dialect == SMB2_DIALECT_30)
            {
                if (_debug) Console.WriteLine("    [KEYS] SMB3 mode; NTLM sessionKey={0}", Smb3Crypto.Hex(sessionKey));
                _smb3SigningKey = Smb3Crypto.KdfCounterMode(sessionKey, Ascii("SMB2AESCMAC\0"), Ascii("SmbSign\0"));
                _encryptionKey = Smb3Crypto.KdfCounterMode(sessionKey, Ascii("SMB2AESCCM\0"), Ascii("ServerIn \0"));
                _decryptionKey = Smb3Crypto.KdfCounterMode(sessionKey, Ascii("SMB2AESCCM\0"), Ascii("ServerOut\0"));
                _encrypt = true;
                if (_debug)
                {
                    Console.WriteLine("    [KEYS] sessionId=0x{0:X16}", _sessionId);
                    Console.WriteLine("    [KEYS] signKey={0} encKey={1} decKey={2}",
                        Smb3Crypto.Hex(_smb3SigningKey), Smb3Crypto.Hex(_encryptionKey), Smb3Crypto.Hex(_decryptionKey));
                }
            }
        }

        private static byte[] Ascii(string s)
        {
            return Encoding.ASCII.GetBytes(s);
        }

        public void DisableSigning()
        {
            _signingKey = null;
        }

        public byte[] SessionSetup(byte[] securityBlob)
        {
            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms))
            {
                bw.Write((ushort)25);  // StructureSize
                bw.Write((byte)0);     // Flags
                bw.Write((byte)0);     // SecurityMode
                bw.Write((uint)0);     // Capabilities
                bw.Write((uint)0);     // Channel
                bw.Write((ushort)88);  // SecurityBufferOffset (header=64 + fixed=24)
                bw.Write((ushort)securityBlob.Length);  // SecurityBufferLength
                bw.Write((ulong)0);    // PreviousSessionId
                bw.Write(securityBlob);

                byte[] response = SendReceive(SMB2_SESSION_SETUP, ms.ToArray());
                uint status = GetStatus(response);
                LastSessionSetupStatus = status;

                // Extract SessionId from response header
                _sessionId = BitConverter.ToUInt64(response, 40);

                if (status != STATUS_SUCCESS && status != STATUS_MORE_PROCESSING_REQUIRED)
                    throw new Exception(string.Format("[X] SMB2 Session Setup failed with status 0x{0:X8}", status));

                // Extract security blob from response
                ushort secBufOffset = BitConverter.ToUInt16(response, SMB2_HEADER_SIZE + 4);
                ushort secBufLen = BitConverter.ToUInt16(response, SMB2_HEADER_SIZE + 6);

                if (secBufLen > 0)
                {
                    byte[] respBlob = new byte[secBufLen];
                    Buffer.BlockCopy(response, secBufOffset, respBlob, 0, secBufLen);
                    return respBlob;
                }

                return null;
            }
        }

        public void TreeConnect(string server)
        {
            string path = string.Format("\\\\{0}\\IPC$", server);
            byte[] pathBytes = Encoding.Unicode.GetBytes(path);

            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms))
            {
                bw.Write((ushort)9);   // StructureSize
                bw.Write((ushort)0);   // Reserved / Flags
                bw.Write((ushort)72);  // PathOffset (header=64 + fixed=8)
                bw.Write((ushort)pathBytes.Length); // PathLength
                bw.Write(pathBytes);

                byte[] response = SendReceive(SMB2_TREE_CONNECT, ms.ToArray());
                uint status = GetStatus(response);
                if (status != STATUS_SUCCESS)
                    throw new Exception(string.Format("[X] SMB2 Tree Connect to IPC$ failed with status 0x{0:X8}", status));

                _treeId = BitConverter.ToUInt32(response, 36);
            }
        }

        public void CreateFile(string pipeName)
        {
            byte[] nameBytes = Encoding.Unicode.GetBytes(pipeName);

            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms))
            {
                bw.Write((ushort)57);   // StructureSize
                bw.Write((byte)0);      // SecurityFlags
                bw.Write((byte)0);      // RequestedOplockLevel (NONE)
                bw.Write((uint)0x02);   // ImpersonationLevel (Impersonation)
                bw.Write((ulong)0);     // SmbCreateFlags
                bw.Write((ulong)0);     // Reserved
                bw.Write((uint)0x0012019F); // DesiredAccess: FILE_READ_DATA|FILE_WRITE_DATA|APPEND|READ_EA|WRITE_EA|READ_ATTR|WRITE_ATTR|READ_CONTROL|SYNCHRONIZE
                bw.Write((uint)0x00);   // FileAttributes (none for pipe)
                bw.Write((uint)0x07);   // ShareAccess (Read|Write|Delete)
                bw.Write((uint)0x01);   // CreateDisposition (FILE_OPEN)
                bw.Write((uint)0x00000040); // CreateOptions (NON_DIRECTORY_FILE)
                ushort nameOffset = (ushort)(SMB2_HEADER_SIZE + 56); // 120
                bw.Write(nameOffset);   // NameOffset
                bw.Write((ushort)nameBytes.Length); // NameLength
                bw.Write((uint)0);      // CreateContextsOffset
                bw.Write((uint)0);      // CreateContextsLength
                bw.Write(nameBytes);

                byte[] response = SendReceive(SMB2_CREATE, ms.ToArray());
                uint status = GetStatus(response);
                if (status != STATUS_SUCCESS)
                    throw new Exception(string.Format("[X] SMB2 Create pipe '{0}' failed with status 0x{1:X8}", pipeName, status));

                // FileId is at response body offset 64 (StructureSize=89, FileId at offset 64 in body)
                _fileId = new byte[16];
                Buffer.BlockCopy(response, SMB2_HEADER_SIZE + 64, _fileId, 0, 16);
            }
        }

        private const uint STATUS_BUFFER_OVERFLOW = 0x80000005;

        // Named-pipe RPC round trip, exactly as impacket's ncacn_np transport does it:
        // one SMB2 WRITE of the full PDU, then one SMB2 READ of the response. The
        // server may answer the READ with an async STATUS_PENDING interim response and
        // then the real data; SendReceive() consumes the interim frame transparently.
        public byte[] TransactNamedPipe(byte[] inputData)
        {
            // SMB2 WRITE — push the RPC request onto the pipe.
            using (var wms = new MemoryStream())
            using (var wbw = new BinaryWriter(wms))
            {
                ushort dataOffset = (ushort)(SMB2_HEADER_SIZE + 48);
                wbw.Write((ushort)49);             // StructureSize
                wbw.Write(dataOffset);             // DataOffset
                wbw.Write((uint)inputData.Length); // Length
                wbw.Write((ulong)0);               // Offset
                wbw.Write(_fileId);                // FileId (16 bytes)
                wbw.Write((uint)0);                // Channel
                wbw.Write((uint)0);                // RemainingBytes
                wbw.Write((ushort)0);              // WriteChannelInfoOffset
                wbw.Write((ushort)0);              // WriteChannelInfoLength
                wbw.Write((uint)0);                // Flags
                wbw.Write(inputData);

                byte[] writeResp = SendReceive(SMB2_WRITE, wms.ToArray());
                uint writeStatus = GetStatus(writeResp);
                if (writeStatus != STATUS_SUCCESS)
                    throw new Exception(string.Format("[X] SMB2 Write failed: 0x{0:X8}", writeStatus));
            }

            // SMB2 READ — pull the RPC response. Read up to 64KB so the whole fragment
            // arrives in one shot (impacket relies on this too).
            byte[] readResp;
            using (var rms = new MemoryStream())
            using (var rbw = new BinaryWriter(rms))
            {
                rbw.Write((ushort)49);   // StructureSize
                rbw.Write((byte)0);      // Padding
                rbw.Write((byte)0);      // Flags
                rbw.Write((uint)65536);  // Length
                rbw.Write((ulong)0);     // Offset
                rbw.Write(_fileId);      // FileId (16 bytes)
                rbw.Write((uint)0);      // MinimumCount
                rbw.Write((uint)0);      // Channel
                rbw.Write((uint)0);      // RemainingBytes
                rbw.Write((ushort)0);    // ReadChannelInfoOffset
                rbw.Write((ushort)0);    // ReadChannelInfoLength
                rbw.Write((byte)0);      // Buffer (minimum 1 byte)

                readResp = SendReceive(SMB2_READ, rms.ToArray());
            }

            uint readStatus = GetStatus(readResp);
            if (readStatus != STATUS_SUCCESS && readStatus != STATUS_BUFFER_OVERFLOW)
                throw new Exception(string.Format("[X] SMB2 Read failed: 0x{0:X8}", readStatus));

            // READ response: StructureSize(2) + DataOffset(1) + Reserved(1) + DataLength(4) + ...
            byte dataOffset2 = readResp[SMB2_HEADER_SIZE + 2];
            uint dataLength = BitConverter.ToUInt32(readResp, SMB2_HEADER_SIZE + 4);

            byte[] output = new byte[dataLength];
            Buffer.BlockCopy(readResp, dataOffset2, output, 0, (int)dataLength);
            return output;
        }

        public void CloseFile()
        {
            if (_fileId == null) return;

            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms))
            {
                bw.Write((ushort)24); // StructureSize
                bw.Write((ushort)0);  // Flags
                bw.Write((uint)0);    // Reserved
                bw.Write(_fileId);    // FileId (16 bytes)

                byte[] response = SendReceive(SMB2_CLOSE, ms.ToArray());
            }
            _fileId = null;
        }

        public void TreeDisconnect()
        {
            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms))
            {
                bw.Write((ushort)4); // StructureSize
                bw.Write((ushort)0); // Reserved

                SendReceive(SMB2_TREE_DISCONNECT, ms.ToArray());
            }
            _treeId = 0;
        }

        public void Logoff()
        {
            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms))
            {
                bw.Write((ushort)4); // StructureSize
                bw.Write((ushort)0); // Reserved

                SendReceive(SMB2_LOGOFF, ms.ToArray());
            }
            _sessionId = 0;
        }

        private const uint SMB2_FLAGS_SIGNED = 0x00000008;

        private byte[] SendReceive(ushort command, byte[] body)
        {
            byte[] header = BuildHeader(command);
            byte[] packet = new byte[header.Length + body.Length];
            Buffer.BlockCopy(header, 0, packet, 0, header.Length);
            Buffer.BlockCopy(body, 0, packet, header.Length, body.Length);

            bool transportSecured = command != SMB2_NEGOTIATE && command != SMB2_SESSION_SETUP;

            // SMB 3.0 encrypted mode: wrap the PDU in an AES-128-CCM SMB2_TRANSFORM_HEADER.
            // The CCM tag provides integrity, so the inner PDU is NOT signed (matches the
            // Windows SMB client on an encrypted session).
            if (_encrypt && transportSecured)
            {
                // HMAC-SHA256 signing only applies to the non-encrypted (SMB 2.x) path.
            }
            else if (_signingKey != null && transportSecured)
            {
                // Set SMB2_FLAGS_SIGNED in the Flags field (offset 16)
                uint flags = BitConverter.ToUInt32(packet, 16);
                flags |= SMB2_FLAGS_SIGNED;
                byte[] flagBytes = BitConverter.GetBytes(flags);
                Buffer.BlockCopy(flagBytes, 0, packet, 16, 4);

                // Zero out the signature field (offset 48, 16 bytes)
                Array.Clear(packet, 48, 16);

                // Compute HMAC-SHA256 signature
                using (var hmac = new HMACSHA256(_signingKey))
                {
                    byte[] sig = hmac.ComputeHash(packet);
                    // Copy first 16 bytes of HMAC to signature field
                    Buffer.BlockCopy(sig, 0, packet, 48, 16);
                }
            }

            // The bytes actually placed on the wire: the encrypted transform frame in SMB3
            // mode, otherwise the (possibly signed) plaintext PDU.
            byte[] toSend = (_encrypt && transportSecured) ? EncryptTransform(packet) : packet;

            // NetBIOS session header (4 bytes, big-endian length)
            byte[] netbios = new byte[4];
            netbios[0] = 0;
            netbios[1] = (byte)((toSend.Length >> 16) & 0xFF);
            netbios[2] = (byte)((toSend.Length >> 8) & 0xFF);
            netbios[3] = (byte)(toSend.Length & 0xFF);

            DumpPacket("SEND", command, packet);

            _stream.Write(netbios, 0, 4);
            _stream.Write(toSend, 0, toSend.Length);
            _stream.Flush();

            // Read response (decrypting the transform frame if the server encrypted it)
            byte[] response = MaybeDecrypt(ReadFrame());
            DumpPacket("RECV", command, response);

            // Handle STATUS_PENDING (0x00000103): the server sent an interim async
            // response and will follow with the real response as a separate frame on
            // the same MessageId. Keep reading frames until we get a final response.
            // The interim response carries SMB2_FLAGS_ASYNC_COMMAND (0x2) and must be
            // skipped — it is not the data we want.
            while (GetStatus(response) == STATUS_PENDING)
            {
                response = MaybeDecrypt(ReadFrame());
                DumpPacket("RECV(pending-followup)", command, response);
            }

            _messageId++;
            return response;
        }

        private const int SMB2_TRANSFORM_HEADER_SIZE = 52;
        private const ushort SMB2_ENCRYPTION_AES128_CCM = 0x0001;

        private static byte[] Slice(byte[] b, int off, int len)
        {
            byte[] r = new byte[len];
            Buffer.BlockCopy(b, off, r, 0, len);
            return r;
        }

        // Wrap a plaintext SMB2 PDU in an encrypted SMB2_TRANSFORM_HEADER (MS-SMB2 2.2.41).
        // Layout: ProtocolId(4 \xfdSMB) | Signature(16) | Nonce(16) | OriginalMessageSize(4)
        //         | Reserved(2) | Flags/EncryptionAlgorithm(2) | SessionId(8). AES-128-CCM
        // uses an 11-byte nonce; the remaining 5 nonce bytes are zero. The AAD is the
        // header from the Nonce field through the SessionId (32 bytes), and the resulting
        // 16-byte CCM tag is written into the Signature field.
        private byte[] EncryptTransform(byte[] plaintext)
        {
            byte[] hdr = new byte[SMB2_TRANSFORM_HEADER_SIZE];
            hdr[0] = 0xFD; hdr[1] = (byte)'S'; hdr[2] = (byte)'M'; hdr[3] = (byte)'B';

            // Nonce: 11 random significant bytes (+5 zero) at offset 20.
            byte[] nonce16 = new byte[16];
            using (var rng = new RNGCryptoServiceProvider())
                rng.GetBytes(nonce16, 0, 11);
            Buffer.BlockCopy(nonce16, 0, hdr, 20, 16);
            byte[] nonce11 = new byte[11];
            Buffer.BlockCopy(hdr, 20, nonce11, 0, 11);

            // OriginalMessageSize
            byte[] sz = BitConverter.GetBytes((uint)plaintext.Length);
            Buffer.BlockCopy(sz, 0, hdr, 36, 4);

            // Flags/EncryptionAlgorithm = AES-128-CCM
            byte[] alg = BitConverter.GetBytes(SMB2_ENCRYPTION_AES128_CCM);
            Buffer.BlockCopy(alg, 0, hdr, 42, 2);

            // SessionId
            byte[] sid = BitConverter.GetBytes(_sessionId);
            Buffer.BlockCopy(sid, 0, hdr, 44, 8);

            byte[] aad = new byte[32];
            Buffer.BlockCopy(hdr, 20, aad, 0, 32);

            byte[] tag;
            byte[] ciphertext = Smb3Crypto.CcmEncrypt(_encryptionKey, nonce11, plaintext, aad, out tag);
            Buffer.BlockCopy(tag, 0, hdr, 4, 16);

            byte[] frame = new byte[SMB2_TRANSFORM_HEADER_SIZE + ciphertext.Length];
            Buffer.BlockCopy(hdr, 0, frame, 0, SMB2_TRANSFORM_HEADER_SIZE);
            Buffer.BlockCopy(ciphertext, 0, frame, SMB2_TRANSFORM_HEADER_SIZE, ciphertext.Length);
            if (_debug)
            {
                Console.WriteLine("    [XFRM-SEND] header={0}", Smb3Crypto.Hex(hdr));
                Console.WriteLine("    [XFRM-SEND] frameLen={0} (hdr52 + ct{1})", frame.Length, ciphertext.Length);
            }
            return frame;
        }

        // If a received frame is an SMB2_TRANSFORM_HEADER, decrypt it back to the inner
        // SMB2 PDU; otherwise return it unchanged.
        private byte[] MaybeDecrypt(byte[] frame)
        {
            if (_debug)
                Console.WriteLine("    [XFRM-RECV] frameLen={0} firstBytes={1}", frame.Length,
                    Smb3Crypto.Hex(frame.Length > 8 ? Slice(frame, 0, 8) : frame));
            if (frame.Length < SMB2_TRANSFORM_HEADER_SIZE ||
                frame[0] != 0xFD || frame[1] != (byte)'S' || frame[2] != (byte)'M' || frame[3] != (byte)'B')
            {
                if (_debug && frame.Length >= 4 && !(frame[0] == 0xFE && frame[1] == (byte)'S'))
                    Console.WriteLine("    [XFRM-RECV] not a transform/SMB2 frame");
                return frame;
            }
            if (_debug) Console.WriteLine("    [XFRM-RECV] transform header={0}", Smb3Crypto.Hex(Slice(frame, 0, SMB2_TRANSFORM_HEADER_SIZE)));

            byte[] tag = new byte[16];
            Buffer.BlockCopy(frame, 4, tag, 0, 16);

            byte[] nonce11 = new byte[11];
            Buffer.BlockCopy(frame, 20, nonce11, 0, 11);

            byte[] aad = new byte[32];
            Buffer.BlockCopy(frame, 20, aad, 0, 32);

            byte[] ciphertext = new byte[frame.Length - SMB2_TRANSFORM_HEADER_SIZE];
            Buffer.BlockCopy(frame, SMB2_TRANSFORM_HEADER_SIZE, ciphertext, 0, ciphertext.Length);

            return Smb3Crypto.CcmDecrypt(_decryptionKey, nonce11, ciphertext, aad, tag);
        }

        // Set RUBEUS_SMB_DEBUG=1 to dump every SMB2 packet header on the wire.
        private static readonly bool _debug =
            Environment.GetEnvironmentVariable("RUBEUS_SMB_DEBUG") == "1";

        private void DumpPacket(string dir, ushort command, byte[] pkt)
        {
            if (!_debug) return;
            if (pkt == null || pkt.Length < SMB2_HEADER_SIZE)
            {
                Console.WriteLine("    [SMB {0}] cmd={1} (short/null packet, len={2})", dir, command, pkt == null ? 0 : pkt.Length);
                return;
            }
            uint status = BitConverter.ToUInt32(pkt, 8);
            ushort cmd = BitConverter.ToUInt16(pkt, 12);
            ushort creditsGranted = BitConverter.ToUInt16(pkt, 14);
            ushort creditCharge = BitConverter.ToUInt16(pkt, 6);
            uint flags = BitConverter.ToUInt32(pkt, 16);
            ulong mid = BitConverter.ToUInt64(pkt, 24);
            Console.WriteLine("    [SMB {0}] cmd=0x{1:X2} status=0x{2:X8} mid={3} creditCharge={4} credits={5} flags=0x{6:X8} len={7}",
                dir, cmd, status, mid, creditCharge, creditsGranted, flags, pkt.Length);
            // First 64 bytes of body for the interesting frames
            int bodyStart = SMB2_HEADER_SIZE;
            int bodyLen = Math.Min(48, pkt.Length - bodyStart);
            if (bodyLen > 0)
            {
                var sb = new StringBuilder("      body: ");
                for (int i = 0; i < bodyLen; i++)
                    sb.AppendFormat("{0:X2}", pkt[bodyStart + i]);
                Console.WriteLine(sb.ToString());
            }
        }

        private const uint STATUS_PENDING = 0x00000103;

        private byte[] ReadFrame()
        {
            byte[] respNetbios = ReadExact(4);
            int respLen = (respNetbios[1] << 16) | (respNetbios[2] << 8) | respNetbios[3];
            return ReadExact(respLen);
        }

        private byte[] BuildHeader(ushort command)
        {
            byte[] header = new byte[SMB2_HEADER_SIZE];
            // ProtocolId
            header[0] = 0xFE;
            header[1] = (byte)'S';
            header[2] = (byte)'M';
            header[3] = (byte)'B';
            // StructureSize
            header[4] = 64;
            header[5] = 0;
            // CreditCharge
            header[6] = 1;
            header[7] = 0;
            // Command
            header[12] = (byte)(command & 0xFF);
            header[13] = (byte)((command >> 8) & 0xFF);
            // Credits requested
            header[14] = 31;
            header[15] = 0;
            // MessageId
            byte[] mid = BitConverter.GetBytes(_messageId);
            Buffer.BlockCopy(mid, 0, header, 24, 8);
            // TreeId
            byte[] tid = BitConverter.GetBytes(_treeId);
            Buffer.BlockCopy(tid, 0, header, 36, 4);
            // SessionId
            byte[] sid = BitConverter.GetBytes(_sessionId);
            Buffer.BlockCopy(sid, 0, header, 40, 8);

            return header;
        }

        private static uint GetStatus(byte[] response)
        {
            return BitConverter.ToUInt32(response, 8);
        }

        private byte[] ReadExact(int count)
        {
            byte[] buf = new byte[count];
            int offset = 0;
            while (offset < count)
            {
                int read = _stream.Read(buf, offset, count - offset);
                if (read == 0)
                    throw new Exception("[X] SMB2 connection closed unexpectedly");
                offset += read;
            }
            return buf;
        }

        public void Dispose()
        {
            try { if (_fileId != null) CloseFile(); } catch { }
            try { if (_treeId != 0) TreeDisconnect(); } catch { }
            try { if (_sessionId != 0) Logoff(); } catch { }
            try { if (_stream != null) _stream.Close(); } catch { }
            try { if (_tcp != null) _tcp.Close(); } catch { }
        }
    }
}
