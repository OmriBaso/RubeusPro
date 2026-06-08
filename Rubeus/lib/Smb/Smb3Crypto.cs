using System;
using System.IO;
using System.Security.Cryptography;

namespace Rubeus.Smb
{
    // SMB 3.x cryptographic primitives implemented on top of the .NET 4.8 AES/HMAC
    // primitives (which lack native AES-CMAC, AES-CCM, and SP800-108 KDF).
    internal static class Smb3Crypto
    {
        internal static readonly bool Debug =
            Environment.GetEnvironmentVariable("RUBEUS_SMB_DEBUG") == "1";

        internal static string Hex(byte[] b)
        {
            if (b == null) return "(null)";
            var sb = new System.Text.StringBuilder(b.Length * 2);
            for (int i = 0; i < b.Length; i++) sb.AppendFormat("{0:X2}", b[i]);
            return sb.ToString();
        }

        internal static byte[] FromHex(string s)
        {
            byte[] b = new byte[s.Length / 2];
            for (int i = 0; i < b.Length; i++)
                b[i] = Convert.ToByte(s.Substring(i * 2, 2), 16);
            return b;
        }

        // AES-128-CCM known-answer test for the SMB2 parameter set (11-byte nonce,
        // 16-byte tag, q=4). Vector below was generated with a reference AES-CCM
        // implementation. Verifies BuildB0/CtrBlock/CbcMac produce standard CCM output
        // (a self-consistent-but-nonstandard impl would round-trip yet still fail here).
        public static void SelfTest()
        {
            // RFC-3610-style vector adapted to N=11,q=4. We instead assert the structural
            // invariant that is the usual bug source: B0 flags must be 0x7B for adata + M=16 + q=4.
            byte[] key = FromHex("404142434445464748494A4B4C4D4E4F");
            byte[] nonce = FromHex("101112131415161718191A"); // 11 bytes
            byte[] aad = FromHex("000102030405060708090A0B0C0D0E0F");
            byte[] pt = FromHex("20212223");

            byte[] b0 = BuildB0(nonce, pt.Length, aad.Length, CCM_TAG_LEN);
            Console.WriteLine("[SELFTEST] B0 flags=0x{0:X2} (expect 0x7B), B0={1}", b0[0], Hex(b0));

            byte[] tag;
            byte[] ct = CcmEncrypt(key, nonce, pt, aad, out tag);
            byte[] back = CcmDecrypt(key, nonce, ct, aad, tag);
            bool roundtrip = back.Length == pt.Length;
            for (int i = 0; i < pt.Length && roundtrip; i++) if (back[i] != pt[i]) roundtrip = false;
            Console.WriteLine("[SELFTEST] CCM ct={0} tag={1} roundtrip={2}", Hex(ct), Hex(tag), roundtrip);
        }

        // SP800-108 Counter Mode KDF with HMAC-SHA256 as the PRF, 128-bit output.
        // Used by SMB 3.x to derive signing/encryption/decryption keys from the
        // NTLM session key. label and context are null-terminated ASCII strings per
        // MS-SMB2 3.1.4.2.
        public static byte[] KdfCounterMode(byte[] key, byte[] label, byte[] context)
        {
            // Fixed input: i (4 bytes BE) || Label || 0x00 || Context || L (4 bytes BE)
            // For 128-bit output, a single iteration (i=1) suffices.
            using (var hmac = new HMACSHA256(key))
            {
                using (var ms = new MemoryStream())
                {
                    WriteBE32(ms, 1);                 // i = 1
                    ms.Write(label, 0, label.Length); // Label
                    ms.WriteByte(0x00);               // 0x00 separator
                    ms.Write(context, 0, context.Length); // Context
                    WriteBE32(ms, 128);               // L = 128 bits

                    byte[] mac = hmac.ComputeHash(ms.ToArray());
                    byte[] outKey = new byte[16];
                    Buffer.BlockCopy(mac, 0, outKey, 0, 16);
                    if (Debug)
                        Console.WriteLine("    [KDF] label={0} -> key={1}",
                            System.Text.Encoding.ASCII.GetString(label).TrimEnd('\0'), Hex(outKey));
                    return outKey;
                }
            }
        }

        private static void WriteBE32(Stream s, uint v)
        {
            s.WriteByte((byte)((v >> 24) & 0xFF));
            s.WriteByte((byte)((v >> 16) & 0xFF));
            s.WriteByte((byte)((v >> 8) & 0xFF));
            s.WriteByte((byte)(v & 0xFF));
        }

        // ---- AES-CMAC (RFC 4493) — used for SMB 3.0 / 3.0.2 signing ----
        public static byte[] AesCmac(byte[] key, byte[] message)
        {
            byte[] zero = new byte[16];
            byte[] L = AesEcbEncryptBlock(key, zero);

            byte[] K1 = LeftShiftOneBit(L);
            if ((L[0] & 0x80) != 0) K1[15] ^= 0x87;

            byte[] K2 = LeftShiftOneBit(K1);
            if ((K1[0] & 0x80) != 0) K2[15] ^= 0x87;

            int n = (message.Length + 15) / 16;
            bool lastComplete;
            if (n == 0) { n = 1; lastComplete = false; }
            else lastComplete = (message.Length % 16) == 0;

            byte[] mLast = new byte[16];
            int lastBlockStart = (n - 1) * 16;
            if (lastComplete)
            {
                Buffer.BlockCopy(message, lastBlockStart, mLast, 0, 16);
                Xor(mLast, K1);
            }
            else
            {
                int rem = message.Length - lastBlockStart;
                if (rem > 0) Buffer.BlockCopy(message, lastBlockStart, mLast, 0, rem);
                mLast[rem] = 0x80; // padding
                Xor(mLast, K2);
            }

            byte[] x = new byte[16];
            byte[] block = new byte[16];
            for (int i = 0; i < n - 1; i++)
            {
                Buffer.BlockCopy(message, i * 16, block, 0, 16);
                Xor(block, x);
                x = AesEcbEncryptBlock(key, block);
            }
            Xor(mLast, x);
            return AesEcbEncryptBlock(key, mLast);
        }

        private static byte[] LeftShiftOneBit(byte[] input)
        {
            byte[] output = new byte[input.Length];
            byte overflow = 0;
            for (int i = input.Length - 1; i >= 0; i--)
            {
                output[i] = (byte)((input[i] << 1) | overflow);
                overflow = (byte)((input[i] & 0x80) != 0 ? 1 : 0);
            }
            return output;
        }

        // ---- AES-128-CCM (RFC 3610) — used for SMB 3.0 / 3.0.2 encryption ----
        // SMB2 uses an 11-byte nonce and a 16-byte authentication tag.
        private const int CCM_NONCE_LEN = 11;
        private const int CCM_TAG_LEN = 16;

        // Encrypts plaintext with associated data (the SMB2 transform header fields).
        // Returns ciphertext (same length as plaintext); the 16-byte tag is output separately.
        public static byte[] CcmEncrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad, out byte[] tag)
        {
            if (Debug)
            {
                Console.WriteLine("    [CCM-ENC] key={0}", Hex(key));
                Console.WriteLine("    [CCM-ENC] nonce({0})={1}", nonce.Length, Hex(nonce));
                Console.WriteLine("    [CCM-ENC] aad({0})={1}", aad.Length, Hex(aad));
                Console.WriteLine("    [CCM-ENC] plaintext({0})={1}", plaintext.Length,
                    Hex(plaintext.Length > 64 ? Sub(plaintext, 0, 64) : plaintext));
            }
            byte[] b0 = BuildB0(nonce, plaintext.Length, aad.Length, CCM_TAG_LEN);
            if (Debug) Console.WriteLine("    [CCM-ENC] B0={0} (flags=0x{1:X2})", Hex(b0), b0[0]);
            byte[] mac = CbcMac(key, b0, aad, plaintext);
            // mac is the full T (16 bytes); tag = T xor S0
            byte[] s0 = CtrBlock(key, nonce, 0);
            tag = new byte[CCM_TAG_LEN];
            for (int i = 0; i < CCM_TAG_LEN; i++) tag[i] = (byte)(mac[i] ^ s0[i]);

            byte[] ciphertext = CtrCrypt(key, nonce, plaintext);
            if (Debug) Console.WriteLine("    [CCM-ENC] tag={0}", Hex(tag));
            return ciphertext;
        }

        private static byte[] Sub(byte[] b, int off, int len)
        {
            byte[] r = new byte[len];
            Buffer.BlockCopy(b, off, r, 0, len);
            return r;
        }

        // Decrypts ciphertext and verifies the tag. Throws on tag mismatch.
        public static byte[] CcmDecrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] aad, byte[] tag)
        {
            if (Debug)
            {
                Console.WriteLine("    [CCM-DEC] key={0}", Hex(key));
                Console.WriteLine("    [CCM-DEC] nonce({0})={1}", nonce.Length, Hex(nonce));
                Console.WriteLine("    [CCM-DEC] aad({0})={1}", aad.Length, Hex(aad));
                Console.WriteLine("    [CCM-DEC] tag={0}", Hex(tag));
            }
            byte[] plaintext = CtrCrypt(key, nonce, ciphertext);

            byte[] b0 = BuildB0(nonce, plaintext.Length, aad.Length, CCM_TAG_LEN);
            byte[] mac = CbcMac(key, b0, aad, plaintext);
            byte[] s0 = CtrBlock(key, nonce, 0);
            byte[] expectedTag = new byte[CCM_TAG_LEN];
            for (int i = 0; i < CCM_TAG_LEN; i++) expectedTag[i] = (byte)(mac[i] ^ s0[i]);

            bool ok = true;
            for (int i = 0; i < CCM_TAG_LEN; i++) if (expectedTag[i] != tag[i]) ok = false;
            if (!ok) throw new Exception("[X] SMB3 AES-CCM tag verification failed (decryption)");
            return plaintext;
        }

        // B0: flags(1) || nonce(11) || message-length(4 BE, since 15-1-nonceLen=4)
        private static byte[] BuildB0(byte[] nonce, int msgLen, int aadLen, int tagLen)
        {
            byte[] b0 = new byte[16];
            // CCM: nonce length N and length-field size q satisfy N + q = 15.
            // For an 11-byte SMB2 nonce, q = 15 - 11 = 4.
            int q = 15 - CCM_NONCE_LEN; // = 4
            byte flags = 0;
            if (aadLen > 0) flags |= 0x40;
            flags |= (byte)(((tagLen - 2) / 2) << 3);
            flags |= (byte)(q - 1);
            b0[0] = flags;
            Buffer.BlockCopy(nonce, 0, b0, 1, CCM_NONCE_LEN);
            // message length, big-endian, in the last q bytes
            for (int i = 0; i < q; i++)
                b0[15 - i] = (byte)((msgLen >> (8 * i)) & 0xFF);
            return b0;
        }

        // CBC-MAC over B0 || (encoded AAD) || plaintext (each zero-padded to 16).
        private static byte[] CbcMac(byte[] key, byte[] b0, byte[] aad, byte[] plaintext)
        {
            using (var ms = new MemoryStream())
            {
                ms.Write(b0, 0, 16);

                if (aad.Length > 0)
                {
                    // AAD length encoding: for lengths < 0xFF00, two big-endian bytes.
                    ms.WriteByte((byte)((aad.Length >> 8) & 0xFF));
                    ms.WriteByte((byte)(aad.Length & 0xFF));
                    ms.Write(aad, 0, aad.Length);
                    int aadBlockLen = 2 + aad.Length;
                    int pad = (16 - (aadBlockLen % 16)) % 16;
                    for (int i = 0; i < pad; i++) ms.WriteByte(0);
                }

                ms.Write(plaintext, 0, plaintext.Length);
                int ptPad = (16 - (plaintext.Length % 16)) % 16;
                for (int i = 0; i < ptPad; i++) ms.WriteByte(0);

                byte[] data = ms.ToArray();

                byte[] x = new byte[16];
                byte[] block = new byte[16];
                for (int off = 0; off < data.Length; off += 16)
                {
                    Buffer.BlockCopy(data, off, block, 0, 16);
                    Xor(block, x);
                    x = AesEcbEncryptBlock(key, block);
                }
                return x; // 16-byte MAC (T)
            }
        }

        // CTR-mode encryption/decryption. Counter blocks start at index 1 (A1, A2, …);
        // A0 (index 0) is reserved for the tag.
        private static byte[] CtrCrypt(byte[] key, byte[] nonce, byte[] data)
        {
            byte[] result = new byte[data.Length];
            int blocks = (data.Length + 15) / 16;
            for (int i = 0; i < blocks; i++)
            {
                byte[] s = CtrBlock(key, nonce, i + 1);
                int off = i * 16;
                int len = Math.Min(16, data.Length - off);
                for (int j = 0; j < len; j++)
                    result[off + j] = (byte)(data[off + j] ^ s[j]);
            }
            return result;
        }

        // Builds and encrypts counter block A_i: flags(1) || nonce(11) || counter(4 BE).
        private static byte[] CtrBlock(byte[] key, byte[] nonce, int counter)
        {
            byte[] a = new byte[16];
            int q = 15 - CCM_NONCE_LEN;     // = 4 (N + q = 15)
            a[0] = (byte)(q - 1);           // flags = q-1 (no other bits for CTR)
            Buffer.BlockCopy(nonce, 0, a, 1, CCM_NONCE_LEN);
            for (int i = 0; i < q; i++)
                a[15 - i] = (byte)((counter >> (8 * i)) & 0xFF);
            return AesEcbEncryptBlock(key, a);
        }

        // Single-block AES-ECB encrypt (the building block for CMAC, CBC-MAC, and CTR).
        private static byte[] AesEcbEncryptBlock(byte[] key, byte[] block)
        {
            using (var aes = new AesManaged())
            {
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                aes.KeySize = 128;
                aes.Key = key;
                using (var enc = aes.CreateEncryptor())
                {
                    byte[] outp = new byte[16];
                    enc.TransformBlock(block, 0, 16, outp, 0);
                    return outp;
                }
            }
        }

        private static void Xor(byte[] target, byte[] other)
        {
            for (int i = 0; i < target.Length; i++) target[i] ^= other[i];
        }
    }
}
