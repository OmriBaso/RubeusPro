using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Asn1;

namespace Rubeus.Smb
{
    internal static class NtlmAuth
    {
        private static readonly byte[] NtlmSignature = Encoding.ASCII.GetBytes("NTLMSSP\0");

        private const uint NEGOTIATE_UNICODE = 0x00000001;
        private const uint NEGOTIATE_OEM = 0x00000002;
        private const uint REQUEST_TARGET = 0x00000004;
        private const uint NEGOTIATE_NTLM = 0x00000200;
        private const uint NEGOTIATE_ALWAYS_SIGN = 0x00008000;
        private const uint NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000;
        private const uint NEGOTIATE_TARGET_INFO = 0x00800000;
        private const uint NEGOTIATE_128 = 0x20000000;
        private const uint NEGOTIATE_KEY_EXCH = 0x40000000;
        private const uint NEGOTIATE_56 = 0x80000000;

        private const string SPNEGO_OID = "1.3.6.1.5.5.2";
        private const string NTLMSSP_OID = "1.3.6.1.4.1.311.2.2.10";

        public static byte[] CreateSpnegoNegTokenInit(byte[] ntlmNegotiate)
        {
            AsnElt mechType = AsnElt.MakeOID(NTLMSSP_OID);
            AsnElt mechTypes = AsnElt.Make(AsnElt.SEQUENCE, mechType);
            AsnElt mechTypesCtx = AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, mechTypes);

            AsnElt mechToken = AsnElt.MakeBlob(ntlmNegotiate);
            AsnElt mechTokenCtx = AsnElt.MakeExplicit(AsnElt.CONTEXT, 2, mechToken);

            AsnElt negTokenInit = AsnElt.Make(AsnElt.SEQUENCE, mechTypesCtx, mechTokenCtx);
            AsnElt negTokenInitCtx = AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, negTokenInit);

            AsnElt spnegoOid = AsnElt.MakeOID(SPNEGO_OID);
            AsnElt spnego = AsnElt.Make(AsnElt.SEQUENCE, spnegoOid, negTokenInitCtx);

            AsnElt appTag = AsnElt.MakeImplicit(AsnElt.APPLICATION, 0, spnego);

            return appTag.Encode();
        }

        public static byte[] CreateSpnegoNegTokenResp(byte[] ntlmAuth)
        {
            AsnElt mechToken = AsnElt.MakeBlob(ntlmAuth);
            AsnElt mechTokenCtx = AsnElt.MakeExplicit(AsnElt.CONTEXT, 2, mechToken);

            AsnElt negTokenResp = AsnElt.Make(AsnElt.SEQUENCE, mechTokenCtx);
            AsnElt negTokenRespCtx = AsnElt.MakeExplicit(AsnElt.CONTEXT, 1, negTokenResp);

            return negTokenRespCtx.Encode();
        }

        public static byte[] ExtractNtlmFromSpnego(byte[] spnegoBlob)
        {
            // Find NTLMSSP signature in raw bytes and extract from there
            for (int i = 0; i <= spnegoBlob.Length - 8; i++)
            {
                if (spnegoBlob[i] == 'N' && spnegoBlob[i + 1] == 'T' &&
                    spnegoBlob[i + 2] == 'L' && spnegoBlob[i + 3] == 'M' &&
                    spnegoBlob[i + 4] == 'S' && spnegoBlob[i + 5] == 'S' &&
                    spnegoBlob[i + 6] == 'P' && spnegoBlob[i + 7] == 0)
                {
                    byte[] ntlm = new byte[spnegoBlob.Length - i];
                    Buffer.BlockCopy(spnegoBlob, i, ntlm, 0, ntlm.Length);
                    return ntlm;
                }
            }
            return null;
        }

        public static byte[] CreateNegotiateMessage()
        {
            uint flags = NEGOTIATE_UNICODE | NEGOTIATE_OEM | REQUEST_TARGET |
                         NEGOTIATE_NTLM | NEGOTIATE_ALWAYS_SIGN |
                         NEGOTIATE_EXTENDED_SESSIONSECURITY |
                         NEGOTIATE_128 | NEGOTIATE_56;

            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms))
            {
                bw.Write(NtlmSignature);
                bw.Write((uint)1); // Type 1
                bw.Write(flags);
                bw.Write((ushort)0); // DomainNameLen
                bw.Write((ushort)0); // DomainNameMaxLen
                bw.Write((uint)0x28); // DomainNameOffset (after version = 40)
                bw.Write((ushort)0); // WorkstationLen
                bw.Write((ushort)0); // WorkstationMaxLen
                bw.Write((uint)0x28); // WorkstationOffset
                // Version (8 bytes)
                bw.Write((byte)10);   // ProductMajorVersion
                bw.Write((byte)0);    // ProductMinorVersion
                bw.Write((ushort)19041); // ProductBuild
                bw.Write((byte)0);
                bw.Write((byte)0);
                bw.Write((byte)0);
                bw.Write((byte)15);   // NTLMRevisionCurrent
                return ms.ToArray();
            }
        }

        public static byte[] CreateAuthenticateMessage(byte[] challengeMessage, string domain, string username, byte[] ntHash, out byte[] sessionKey)
        {
            ChallengeInfo challenge = ParseChallenge(challengeMessage);

            byte[] ntlmv2Hash = NtlmV2Hash(ntHash, username, domain);
            byte[] clientChallenge = new byte[8];
            using (var rng = new RNGCryptoServiceProvider())
                rng.GetBytes(clientChallenge);

            byte[] ntlmv2Response = ComputeNtlmV2Response(ntlmv2Hash, challenge.ServerChallenge,
                clientChallenge, challenge.AvPairs, challenge.Timestamp);

            byte[] sessionBaseKey;
            using (var hmac = new HMACMD5(ntlmv2Hash))
                sessionBaseKey = hmac.ComputeHash(ntlmv2Response, 0, 16);

            byte[] exportedSessionKey;
            byte[] encryptedRandomSessionKey;

            if ((challenge.NegotiateFlags & NEGOTIATE_KEY_EXCH) != 0)
            {
                exportedSessionKey = new byte[16];
                using (var rng = new RNGCryptoServiceProvider())
                    rng.GetBytes(exportedSessionKey);
                encryptedRandomSessionKey = RC4(sessionBaseKey, exportedSessionKey);
            }
            else
            {
                exportedSessionKey = sessionBaseKey;
                encryptedRandomSessionKey = new byte[0];
            }
            sessionKey = exportedSessionKey;

            byte[] domainBytes = Encoding.Unicode.GetBytes(domain.ToUpper());
            byte[] userBytes = Encoding.Unicode.GetBytes(username);
            byte[] workstationBytes = Encoding.Unicode.GetBytes("");

            uint flags = challenge.NegotiateFlags;

            // Fixed header: Signature(8) + Type(4) + 6*SecurityBuffer(48) + Flags(4) + Version(8) = 72
            // No MIC field — only needed when NEGOTIATE_TARGET_INFO with MsvAvFlags is present
            int payloadOffset = 72;
            int offset = payloadOffset;

            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms))
            {
                bw.Write(NtlmSignature);
                bw.Write((uint)3); // Type 3

                // LmChallengeResponse — 24 bytes of zeros for NTLMv2 compatibility
                byte[] lmResponse = new byte[24];
                bw.Write((ushort)lmResponse.Length);
                bw.Write((ushort)lmResponse.Length);
                bw.Write((uint)offset);
                offset += lmResponse.Length;

                // NtChallengeResponse
                int ntRespLen = ntlmv2Response.Length;
                bw.Write((ushort)ntRespLen);
                bw.Write((ushort)ntRespLen);
                bw.Write((uint)offset);
                offset += ntRespLen;

                // DomainName
                bw.Write((ushort)domainBytes.Length);
                bw.Write((ushort)domainBytes.Length);
                bw.Write((uint)offset);
                offset += domainBytes.Length;

                // UserName
                bw.Write((ushort)userBytes.Length);
                bw.Write((ushort)userBytes.Length);
                bw.Write((uint)offset);
                offset += userBytes.Length;

                // Workstation
                bw.Write((ushort)workstationBytes.Length);
                bw.Write((ushort)workstationBytes.Length);
                bw.Write((uint)offset);
                offset += workstationBytes.Length;

                // EncryptedRandomSessionKey
                bw.Write((ushort)encryptedRandomSessionKey.Length);
                bw.Write((ushort)encryptedRandomSessionKey.Length);
                bw.Write((uint)offset);

                // NegotiateFlags
                bw.Write(flags);

                // Version (8 bytes): 10.0.19041, NTLMSSP revision 15
                bw.Write((byte)10);   // ProductMajorVersion
                bw.Write((byte)0);    // ProductMinorVersion
                bw.Write((ushort)19041); // ProductBuild
                bw.Write((byte)0);    // Reserved
                bw.Write((byte)0);    // Reserved
                bw.Write((byte)0);    // Reserved
                bw.Write((byte)15);   // NTLMRevisionCurrent

                // Payload
                bw.Write(lmResponse);
                bw.Write(ntlmv2Response);
                bw.Write(domainBytes);
                bw.Write(userBytes);
                bw.Write(workstationBytes);
                bw.Write(encryptedRandomSessionKey);

                return ms.ToArray();
            }
        }

        private struct ChallengeInfo
        {
            public uint NegotiateFlags;
            public byte[] ServerChallenge;
            public byte[] AvPairs;
            public long Timestamp;
        }

        private static ChallengeInfo ParseChallenge(byte[] data)
        {
            var info = new ChallengeInfo();
            info.NegotiateFlags = BitConverter.ToUInt32(data, 20);
            info.ServerChallenge = new byte[8];
            Buffer.BlockCopy(data, 24, info.ServerChallenge, 0, 8);

            // TargetInfo fields at offset 40
            ushort targetInfoLen = BitConverter.ToUInt16(data, 40);
            uint targetInfoOffset = BitConverter.ToUInt32(data, 44);

            if (targetInfoLen > 0 && targetInfoOffset + targetInfoLen <= data.Length)
            {
                info.AvPairs = new byte[targetInfoLen];
                Buffer.BlockCopy(data, (int)targetInfoOffset, info.AvPairs, 0, targetInfoLen);
                info.Timestamp = ExtractTimestampFromAvPairs(info.AvPairs);
            }
            else
            {
                info.AvPairs = new byte[0];
                info.Timestamp = DateTime.UtcNow.ToFileTimeUtc();
            }

            return info;
        }

        private static long ExtractTimestampFromAvPairs(byte[] avPairs)
        {
            int pos = 0;
            while (pos + 4 <= avPairs.Length)
            {
                ushort avId = BitConverter.ToUInt16(avPairs, pos);
                ushort avLen = BitConverter.ToUInt16(avPairs, pos + 2);
                if (avId == 0x0007 && avLen == 8 && pos + 4 + 8 <= avPairs.Length) // MsvAvTimestamp
                    return BitConverter.ToInt64(avPairs, pos + 4);
                if (avId == 0x0000) break; // MsvAvEOL
                pos += 4 + avLen;
            }
            return DateTime.UtcNow.ToFileTimeUtc();
        }

        private static byte[] ComputeNtlmV2Response(byte[] ntlmv2Hash, byte[] serverChallenge,
            byte[] clientChallenge, byte[] avPairs, long timestamp)
        {
            // Build NTLMv2 client blob
            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms))
            {
                bw.Write((byte)0x01); // RespType
                bw.Write((byte)0x01); // HiRespType
                bw.Write((ushort)0);  // Reserved1
                bw.Write((uint)0);    // Reserved2
                bw.Write(timestamp);
                bw.Write(clientChallenge);
                bw.Write((uint)0);    // Reserved3
                bw.Write(avPairs);

                byte[] clientBlob = ms.ToArray();

                // Concat serverChallenge + clientBlob, HMAC-MD5 with ntlmv2Hash
                byte[] combined = new byte[serverChallenge.Length + clientBlob.Length];
                Buffer.BlockCopy(serverChallenge, 0, combined, 0, serverChallenge.Length);
                Buffer.BlockCopy(clientBlob, 0, combined, serverChallenge.Length, clientBlob.Length);

                byte[] ntProofStr;
                using (var hmac = new HMACMD5(ntlmv2Hash))
                    ntProofStr = hmac.ComputeHash(combined);

                byte[] ntlmv2Response = new byte[ntProofStr.Length + clientBlob.Length];
                Buffer.BlockCopy(ntProofStr, 0, ntlmv2Response, 0, ntProofStr.Length);
                Buffer.BlockCopy(clientBlob, 0, ntlmv2Response, ntProofStr.Length, clientBlob.Length);

                return ntlmv2Response;
            }
        }

        private static byte[] NtlmV2Hash(byte[] ntHash, string username, string domain)
        {
            byte[] identity = Encoding.Unicode.GetBytes(username.ToUpper() + domain.ToUpper());
            using (var hmac = new HMACMD5(ntHash))
                return hmac.ComputeHash(identity);
        }

        private static byte[] RC4(byte[] key, byte[] data)
        {
            byte[] s = new byte[256];
            for (int i = 0; i < 256; i++) s[i] = (byte)i;
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + s[i] + key[i % key.Length]) & 0xFF;
                byte tmp = s[i]; s[i] = s[j]; s[j] = tmp;
            }
            byte[] result = new byte[data.Length];
            int x = 0, y = 0;
            for (int i = 0; i < data.Length; i++)
            {
                x = (x + 1) & 0xFF;
                y = (y + s[x]) & 0xFF;
                byte tmp = s[x]; s[x] = s[y]; s[y] = tmp;
                result[i] = (byte)(data[i] ^ s[(s[x] + s[y]) & 0xFF]);
            }
            return result;
        }
    }
}
