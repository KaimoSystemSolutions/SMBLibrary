/* Copyright (C) 2017-2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Collections.Generic;
using System.IO;
using SMBLibrary.RPC;

namespace SMBLibrary.Services
{
    public class RPCPipeStream : Stream
    {
        private RemoteService m_service;
        private List<MemoryStream> m_outputStreams;
        private int? m_maxTransmitFragmentSize;

        // NEW — username of the SMB session that owns this pipe instance.
        // Set by the pipe store at handle creation and stays for the lifetime
        // of this stream. One stream = one SMB open = one user.
        private string m_username;

        public RPCPipeStream(RemoteService service) : this(service, null) { }

        public RPCPipeStream(RemoteService service, string username)
        {
            m_service = service;
            m_username = username;
            m_outputStreams = new List<MemoryStream>();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (m_outputStreams.Count > 0)
            {
                int result = m_outputStreams[0].Read(buffer, offset, count);
                if (m_outputStreams[0].Position == m_outputStreams[0].Length)
                    m_outputStreams.RemoveAt(0);
                return result;
            }
            return 0;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            RPCPDU rpcRequest = RPCPDU.GetPDU(buffer, offset);
            ProcessRPCRequest(rpcRequest);
        }

        private void ProcessRPCRequest(RPCPDU rpcRequest)
        {
            if (rpcRequest is BindPDU)
            {
                BindAckPDU bindAckPDU = RemoteServiceHelper.GetRPCBindResponse((BindPDU)rpcRequest, m_service);
                m_maxTransmitFragmentSize = bindAckPDU.MaxTransmitFragmentSize;
                Append(bindAckPDU.GetBytes());
            }
            else if (m_maxTransmitFragmentSize.HasValue && rpcRequest is RequestPDU)
            {
                // CHANGED: pass username down so ABE-aware services get the caller identity.
                List<RPCPDU> responsePDUs = RemoteServiceHelper.GetRPCResponse(
                    (RequestPDU)rpcRequest, m_service, m_maxTransmitFragmentSize.Value, m_username);
                foreach (RPCPDU responsePDU in responsePDUs)
                    Append(responsePDU.GetBytes());
            }
            else
            {
                FaultPDU faultPDU = new FaultPDU();
                faultPDU.Flags = PacketFlags.FirstFragment | PacketFlags.LastFragment;
                faultPDU.DataRepresentation = new DataRepresentationFormat(
                    CharacterFormat.ASCII, ByteOrder.LittleEndian, FloatingPointRepresentation.IEEE);
                faultPDU.CallID = 0;
                faultPDU.AllocationHint = RPCPDU.CommonFieldsLength + FaultPDU.FaultFieldsLength;
                faultPDU.Status = FaultStatus.ProtocolError;
                Append(faultPDU.GetBytes());
            }
        }

        private void Append(byte[] buffer)
        {
            m_outputStreams.Add(new MemoryStream(buffer));
        }

        public override void Flush() { }
        public override void Close() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        public override bool CanSeek => false;
        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public int MessageLength
            => m_outputStreams.Count > 0 ? (int)m_outputStreams[0].Length : 0;
    }
}
