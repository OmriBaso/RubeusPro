using System;
using System.IO;

namespace Rubeus.Smb
{
    internal static class DceRpc
    {
        private const byte RPC_VERSION = 5;
        private const byte RPC_VERSION_MINOR = 0;

        private const byte PACKET_TYPE_BIND = 11;
        private const byte PACKET_TYPE_BIND_ACK = 12;
        private const byte PACKET_TYPE_REQUEST = 0;
        private const byte PACKET_TYPE_RESPONSE = 2;
        private const byte PACKET_TYPE_FAULT = 3;

        private const byte PFC_FIRST_FRAG = 0x01;
        private const byte PFC_LAST_FRAG = 0x03;

        // NDR transfer syntax UUID
        private static readonly Guid NDR_UUID = new Guid("8a885d04-1ceb-11c9-9fe8-08002b104860");
        private const ushort NDR_VERSION = 2;

        public static byte[] CreateBindPdu(Guid interfaceId, ushort majorVersion, ushort minorVersion, uint callId = 1)
        {
            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms))
            {
                // Common header (will fix frag_length later)
                bw.Write(RPC_VERSION);           // rpc_vers
                bw.Write(RPC_VERSION_MINOR);     // rpc_vers_minor
                bw.Write(PACKET_TYPE_BIND);      // PTYPE
                // Cast to byte: `byte | byte` promotes to int in C#, which would
                // select BinaryWriter.Write(int) and emit 4 bytes instead of 1,
                // shifting every following field and corrupting the PDU.
                bw.Write((byte)(PFC_FIRST_FRAG | PFC_LAST_FRAG)); // pfc_flags
                bw.Write(new byte[] { 0x10, 0x00, 0x00, 0x00 }); // data_rep (little-endian, ASCII, IEEE float)
                bw.Write((ushort)0);             // frag_length (placeholder)
                bw.Write((ushort)0);             // auth_length
                bw.Write(callId);                // call_id

                // Bind-specific fields
                bw.Write((ushort)4280);          // max_xmit_frag
                bw.Write((ushort)4280);          // max_recv_frag
                bw.Write((uint)0);               // assoc_group_id

                // p_context_list
                bw.Write((byte)1);               // n_context_elem
                bw.Write((byte)0);               // reserved
                bw.Write((ushort)0);             // reserved2

                // p_cont_elem[0]
                bw.Write((ushort)0);             // p_cont_id
                bw.Write((byte)1);               // n_transfer_syn
                bw.Write((byte)0);               // reserved

                // abstract_syntax (interface UUID + version)
                bw.Write(interfaceId.ToByteArray());
                bw.Write(majorVersion);
                bw.Write(minorVersion);

                // transfer_syntax[0] (NDR)
                bw.Write(NDR_UUID.ToByteArray());
                bw.Write(NDR_VERSION);
                bw.Write((ushort)0);             // minor version

                byte[] pdu = ms.ToArray();
                // Fix frag_length
                ushort fragLen = (ushort)pdu.Length;
                pdu[8] = (byte)(fragLen & 0xFF);
                pdu[9] = (byte)((fragLen >> 8) & 0xFF);
                return pdu;
            }
        }

        public static void ValidateBindAck(byte[] data)
        {
            if (data.Length < 16)
                throw new Exception("[X] DCE/RPC Bind ACK too short");
            if (data[2] != PACKET_TYPE_BIND_ACK)
                throw new Exception(string.Format("[X] Expected DCE/RPC Bind ACK (type {0}), got type {1}", PACKET_TYPE_BIND_ACK, data[2]));

            // Check context negotiation result at offset 36 + 2 (result field)
            // Bind ACK: header(16) + max_xmit(2) + max_recv(2) + assoc(4) + sec_addr_len(2) + sec_addr + padding + results
            // Simplified: just check we got a bind ack, the SAMR operations will fail with clear errors if negotiation failed
        }

        public static byte[] CreateRequestPdu(ushort opnum, byte[] stubData, uint callId = 1)
        {
            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms))
            {
                // Common header
                bw.Write(RPC_VERSION);
                bw.Write(RPC_VERSION_MINOR);
                bw.Write(PACKET_TYPE_REQUEST);
                bw.Write((byte)(PFC_FIRST_FRAG | PFC_LAST_FRAG)); // 1 byte — see CreateBindPdu note
                bw.Write(new byte[] { 0x10, 0x00, 0x00, 0x00 }); // data_rep
                bw.Write((ushort)0);             // frag_length (placeholder)
                bw.Write((ushort)0);             // auth_length
                bw.Write(callId);                // call_id

                // Request-specific fields
                bw.Write((uint)stubData.Length);  // alloc_hint
                bw.Write((ushort)0);             // p_cont_id
                bw.Write(opnum);                 // opnum
                bw.Write(stubData);

                byte[] pdu = ms.ToArray();
                ushort fragLen = (ushort)pdu.Length;
                pdu[8] = (byte)(fragLen & 0xFF);
                pdu[9] = (byte)((fragLen >> 8) & 0xFF);
                return pdu;
            }
        }

        public static byte[] ParseResponseStub(byte[] data)
        {
            if (data.Length < 24)
                throw new Exception("[X] DCE/RPC response too short");

            byte ptype = data[2];
            if (ptype == PACKET_TYPE_FAULT)
            {
                uint faultStatus = 0;
                if (data.Length >= 28)
                    faultStatus = BitConverter.ToUInt32(data, 24);
                throw new Exception(string.Format("[X] DCE/RPC fault: status 0x{0:X8}", faultStatus));
            }

            if (ptype != PACKET_TYPE_RESPONSE)
                throw new Exception(string.Format("[X] Expected DCE/RPC response (type {0}), got type {1}", PACKET_TYPE_RESPONSE, ptype));

            // Response stub starts at offset 24 (header=16 + alloc_hint=4 + cont_id=2 + cancel_count=1 + reserved=1)
            int stubOffset = 24;
            int stubLen = data.Length - stubOffset;
            byte[] stub = new byte[stubLen];
            Buffer.BlockCopy(data, stubOffset, stub, 0, stubLen);
            return stub;
        }
    }
}
