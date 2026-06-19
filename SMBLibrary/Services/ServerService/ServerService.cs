/* Copyright (C) 2014-2024 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Collections.Generic;

namespace SMBLibrary.Services
{
    /// <summary>Legacy provider — returns all shares regardless of caller.</summary>
    public delegate List<string> ShareListProvider();

    /// <summary>
    /// User-aware provider — returns only the shares the given user may see.
    /// Used by Access-Based Enumeration (ABE).
    /// The username may be null or empty for anonymous / pre-auth calls;
    /// in that case the provider should return a safe default
    /// (typically: all shares, since the real access check happens on tree connect).
    /// </summary>
    public delegate List<string> ShareListProviderForUser(string username);

    /// <summary>
    /// [MS-SRVS]
    /// </summary>
    public class ServerService : RemoteService
    {
        public const string ServicePipeName = @"srvsvc";
        public static readonly Guid ServiceInterfaceGuid = new Guid("4B324FC8-1670-01D3-1278-5A47BF6EE188");
        public const int ServiceVersion = 3;
        public const int MaxPreferredLength = -1;

        private PlatformName m_platformID;
        private string m_serverName;
        private uint m_verMajor;
        private uint m_verMinor;
        private ServerType m_serverType;

        private List<string> m_shares;
        private ShareListProvider m_sharesProvider;
        private ShareListProviderForUser m_userSharesProvider; // NEW

        public ServerService(string serverName, List<string> shares)
        {
            InitMetadata(serverName);
            m_shares = shares;
        }

        public ServerService(string serverName, ShareListProvider sharesProvider)
        {
            InitMetadata(serverName);
            m_sharesProvider = sharesProvider;
        }

        // NEW constructor
        public ServerService(string serverName, ShareListProviderForUser userSharesProvider)
        {
            InitMetadata(serverName);
            m_userSharesProvider = userSharesProvider;
        }

        private void InitMetadata(string serverName)
        {
            m_platformID = PlatformName.NT;
            m_serverName = serverName;
            m_verMajor = 5;
            m_verMinor = 2;
            m_serverType = ServerType.Workstation | ServerType.Server
                         | ServerType.WindowsNT | ServerType.ServerNT
                         | ServerType.MasterBrowser;
        }

        // Legacy entry — no username known, falls back to "all shares" behavior.
        public override byte[] GetResponseBytes(ushort opNum, byte[] requestBytes)
        {
            return GetResponseBytes(opNum, requestBytes, null);
        }

        // NEW user-aware entry — used by ABE
        public override byte[] GetResponseBytes(ushort opNum, byte[] requestBytes, string username)
        {
            switch ((ServerServiceOpName)opNum)
            {
                case ServerServiceOpName.NetrShareEnum:
                    {
                        NetrShareEnumResponse response = GetNetrShareEnumResponse(requestBytes, username);
                        return response.GetBytes();
                    }
                case ServerServiceOpName.NetrShareGetInfo:
                    {
                        NetrShareGetInfoRequest request = new NetrShareGetInfoRequest(requestBytes);
                        NetrShareGetInfoResponse response = GetNetrShareGetInfoResponse(request, username);
                        return response.GetBytes();
                    }
                case ServerServiceOpName.NetrServerGetInfo:
                    {
                        NetrServerGetInfoRequest request = new NetrServerGetInfoRequest(requestBytes);
                        NetrServerGetInfoResponse response = GetNetrWkstaGetInfoResponse(request);
                        return response.GetBytes();
                    }
                default:
                    throw new UnsupportedOpNumException();
            }
        }

        // Backwards-compatible public method kept for any external caller
        public NetrShareEnumResponse GetNetrShareEnumResponse(byte[] requestBytes)
        {
            return GetNetrShareEnumResponse(requestBytes, null);
        }

        public NetrShareEnumResponse GetNetrShareEnumResponse(byte[] requestBytes, string username)
        {
            NetrShareEnumRequest request;
            NetrShareEnumResponse response = new NetrShareEnumResponse();
            try
            {
                request = new NetrShareEnumRequest(requestBytes);
            }
            catch (UnsupportedLevelException ex)
            {
                response.InfoStruct = new ShareEnum(ex.Level);
                response.Result = Win32Error.ERROR_NOT_SUPPORTED;
                return response;
            }
            catch (InvalidLevelException ex)
            {
                response.InfoStruct = new ShareEnum(ex.Level);
                response.Result = Win32Error.ERROR_INVALID_LEVEL;
                return response;
            }

            switch (request.InfoStruct.Level)
            {
                case 0:
                    {
                        List<string> shares = GetCurrentShares(username);
                        ShareInfo0Container info = new ShareInfo0Container();
                        foreach (string shareName in shares)
                            info.Add(new ShareInfo0Entry(shareName));
                        response.InfoStruct = new ShareEnum(info);
                        response.TotalEntries = (uint)shares.Count;
                        response.Result = Win32Error.ERROR_SUCCESS;
                        return response;
                    }
                case 1:
                    {
                        List<string> shares = GetCurrentShares(username);
                        ShareInfo1Container info = new ShareInfo1Container();
                        foreach (string shareName in shares)
                            info.Add(new ShareInfo1Entry(shareName, new ShareTypeExtended(ShareType.DiskDrive)));
                        response.InfoStruct = new ShareEnum(info);
                        response.TotalEntries = (uint)shares.Count;
                        response.Result = Win32Error.ERROR_SUCCESS;
                        return response;
                    }
                case 2:
                case 501:
                case 502:
                case 503:
                    response.InfoStruct = new ShareEnum(request.InfoStruct.Level);
                    response.Result = Win32Error.ERROR_NOT_SUPPORTED;
                    return response;
                default:
                    response.InfoStruct = new ShareEnum(request.InfoStruct.Level);
                    response.Result = Win32Error.ERROR_INVALID_LEVEL;
                    return response;
            }
        }

        // Backwards-compatible
        public NetrShareGetInfoResponse GetNetrShareGetInfoResponse(NetrShareGetInfoRequest request)
        {
            return GetNetrShareGetInfoResponse(request, null);
        }

        public NetrShareGetInfoResponse GetNetrShareGetInfoResponse(
            NetrShareGetInfoRequest request, string username)
        {
            List<string> shares = GetCurrentShares(username);
            int shareIndex = -1;
            for (int i = 0; i < shares.Count; i++)
            {
                if (shares[i].Equals(request.NetName, StringComparison.OrdinalIgnoreCase))
                {
                    shareIndex = i;
                    break;
                }
            }

            NetrShareGetInfoResponse response = new NetrShareGetInfoResponse();
            if (shareIndex == -1)
            {
                response.InfoStruct = new ShareInfo(request.Level);
                response.Result = Win32Error.NERR_NetNameNotFound;
                return response;
            }

            switch (request.Level)
            {
                case 0:
                    response.InfoStruct = new ShareInfo(new ShareInfo0Entry(shares[shareIndex]));
                    response.Result = Win32Error.ERROR_SUCCESS;
                    return response;
                case 1:
                    response.InfoStruct = new ShareInfo(new ShareInfo1Entry(
                        shares[shareIndex], new ShareTypeExtended(ShareType.DiskDrive)));
                    response.Result = Win32Error.ERROR_SUCCESS;
                    return response;
                case 2:
                    response.InfoStruct = new ShareInfo(new ShareInfo2Entry(
                        shares[shareIndex], new ShareTypeExtended(ShareType.DiskDrive)));
                    response.Result = Win32Error.ERROR_SUCCESS;
                    return response;
                case 501:
                case 502:
                case 503:
                case 1005:
                    response.InfoStruct = new ShareInfo(request.Level);
                    response.Result = Win32Error.ERROR_NOT_SUPPORTED;
                    return response;
                default:
                    response.InfoStruct = new ShareInfo(request.Level);
                    response.Result = Win32Error.ERROR_INVALID_LEVEL;
                    return response;
            }
        }

        public NetrServerGetInfoResponse GetNetrWkstaGetInfoResponse(NetrServerGetInfoRequest request)
        {
            // unchanged
            NetrServerGetInfoResponse response = new NetrServerGetInfoResponse();
            switch (request.Level)
            {
                case 100:
                    {
                        ServerInfo100 info = new ServerInfo100();
                        info.PlatformID = m_platformID;
                        info.ServerName.Value = m_serverName;
                        response.InfoStruct = new ServerInfo(info);
                        response.Result = Win32Error.ERROR_SUCCESS;
                        return response;
                    }
                case 101:
                    {
                        ServerInfo101 info = new ServerInfo101();
                        info.PlatformID = m_platformID;
                        info.ServerName.Value = m_serverName;
                        info.VerMajor = m_verMajor;
                        info.VerMinor = m_verMinor;
                        info.Type = m_serverType;
                        info.Comment.Value = String.Empty;
                        response.InfoStruct = new ServerInfo(info);
                        response.Result = Win32Error.ERROR_SUCCESS;
                        return response;
                    }
                case 102:
                case 103:
                case 502:
                case 503:
                    response.InfoStruct = new ServerInfo(request.Level);
                    response.Result = Win32Error.ERROR_NOT_SUPPORTED;
                    return response;
                default:
                    response.InfoStruct = new ServerInfo(request.Level);
                    response.Result = Win32Error.ERROR_INVALID_LEVEL;
                    return response;
            }
        }

        /// <summary>
        /// Provider priority:
        ///   1. User-aware provider (if username present)  → ABE-filtered list
        ///   2. Legacy provider (any state)                → static list
        ///   3. Hard-coded list                            → constructor input
        ///   4. Empty list                                 → safe fallback
        /// </summary>
        private List<string> GetCurrentShares(string username)
        {
            if (m_userSharesProvider != null)
                return m_userSharesProvider(username) ?? new List<string>();
            if (m_sharesProvider != null)
                return m_sharesProvider() ?? new List<string>();
            return m_shares ?? new List<string>();
        }

        // Legacy overload for any external caller that grew on this codebase
        private List<string> GetCurrentShares()
        {
            return GetCurrentShares(null);
        }

        public override Guid InterfaceGuid => ServiceInterfaceGuid;
        public override string PipeName => ServicePipeName;
    }
}