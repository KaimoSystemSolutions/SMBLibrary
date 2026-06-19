/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Utilities;

namespace SMBLibrary.Services
{
    public abstract class RemoteService
    {
        /// <summary>
        /// Legacy entry point — implementations that don't need the caller's
        /// identity only need to implement this overload.
        /// </summary>
        public abstract byte[] GetResponseBytes(ushort opNum, byte[] requestBytes);

        /// <summary>
        /// User-aware entry point. Default forwards to the legacy method,
        /// so existing implementations continue to work unchanged.
        /// Override this when the response depends on the caller (e.g. ABE).
        /// </summary>
        public virtual byte[] GetResponseBytes(ushort opNum, byte[] requestBytes, string username)
        {
            return GetResponseBytes(opNum, requestBytes);
        }

        public abstract Guid InterfaceGuid { get; }
        public abstract string PipeName { get; }
    }
}
