/*
 * Wazuh remoted module - Control endpoint types
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_CONTROL_TYPES_HPP
#define _REMOTED_CONTROL_TYPES_HPP

#include "json.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

namespace remoted::control
{
    using AgentId = std::uint32_t;

    inline constexpr size_t kMaxHostnameLength = 255;
    inline constexpr size_t kMaxIpLength = 45; // IPv6 max
    inline constexpr size_t kMaxOsFieldLength = 128;
    inline constexpr size_t kMaxVersionLength = 64;

    enum class SocketError
    {
        None,
        Timeout,
        ClosedByPeer,
        ProtocolError,
        ConnectRefused,
        Io,
        QueueFull,
        Stopping ///< The client is draining/shutting down. Distinct from Io so a caller can
                 ///< recognise a clean-shutdown drain instead of a genuine transport failure.
    };

    struct HostInfo
    {
        std::string hostname;
        std::string architecture;
        std::string ip;
        std::string osName;
        std::string osVersion;
        std::string osPlatform;
        std::string osType;
    };

    struct StartupData
    {
        std::string version;
    };

    struct NotifyData
    {
        std::string version;
        std::optional<HostInfo> host;
    };

    struct ShutdownData
    {
    };

    inline bool isValidHostInfo(const HostInfo& h)
    {
        return h.hostname.size() <= kMaxHostnameLength && h.ip.size() <= kMaxIpLength &&
               h.osName.size() <= kMaxOsFieldLength && h.osVersion.size() <= kMaxOsFieldLength &&
               h.architecture.size() <= kMaxOsFieldLength && h.osPlatform.size() <= kMaxOsFieldLength &&
               h.osType.size() <= kMaxOsFieldLength;
    }

    inline bool isValidVersion(const std::string& version)
    {
        if (version.empty() || version.size() > kMaxVersionLength)
        {
            return false;
        }

        static const std::regex versionRegex(R"(^[vV]?\d+(\.\d+){0,3}([+\-][A-Za-z0-9.\-]+)?$)");
        return std::regex_match(version, versionRegex);
    }

    /**
     * @brief Generic numeric comparison of MAJOR.MINOR.PATCH[.EXTRA] version strings.
     *
     * Everything after '-'/'+' is discarded. This compares ALL four numeric parts; it is
     * deliberately NOT the allow_higher_versions policy. (An earlier version of this comment
     * claimed it matched "the legacy behavior of compare_wazuh_versions(..., false)" -- it does
     * not: that third parameter is `compare_patch`, and passing `false` there means the legacy
     * callers ignore the patch entirely. See isAgentVersionNewer().)
     *
     * @return -1 if v1 < v2, 1 if v1 > v2, 0 if equal (each unparsed/missing part treated as 0).
     */
    inline int compareVersions(const std::string& v1, const std::string& v2)
    {
        auto parseParts = [](const std::string& v) -> std::array<int, 4>
        {
            std::array<int, 4> parts {0, 0, 0, 0};
            // Strip leading 'v' or 'V' if present
            std::string version = v;
            if (!version.empty() && (version[0] == 'v' || version[0] == 'V'))
            {
                version = version.substr(1);
            }

            size_t pos = version.find_first_of("+-");
            std::string numericPart = (pos != std::string::npos) ? version.substr(0, pos) : version;

            std::istringstream iss(numericPart);
            std::string token;
            int i = 0;
            while (std::getline(iss, token, '.') && i < static_cast<int>(parts.size()))
            {
                try
                {
                    parts[i++] = std::stoi(token);
                }
                catch (...)
                {
                    break;
                }
            }
            return parts;
        };

        auto p1 = parseParts(v1);
        auto p2 = parseParts(v2);

        for (size_t i = 0; i < p1.size(); ++i)
        {
            if (p1[i] < p2[i])
                return -1;
            if (p1[i] > p2[i])
                return 1;
        }
        return 0;
    }

    /**
     * @brief The allow_higher_versions policy check: is the agent's version newer than the
     * manager's?
     *
     * Compares ONLY the major and minor components, mirroring the legacy rule in
     * compare_wazuh_versions(..., compare_patch=false) used by the port 1515 enrollment
     * path (src/os_auth/src/auth.c) and the port 1514 HC_STARTUP path (src/remoted/src/manager.c):
     * an agent one patch release ahead of the manager is accepted. The HTTPS /control and
     * /enroll paths must apply the same rule -- previously they used compareVersions(), which
     * compares all four parts and rejected a 5.0.1 agent against a 5.0.0 manager with a 409/400.
     *
     * compareVersions() stays the generic four-part numeric comparator; this is the policy,
     * kept in one place so /control and /enroll can never silently diverge on what "too new"
     * means.
     *
     * Callers must only pass versions that passed isValidVersion() first.
     */
    inline bool isAgentVersionNewer(const std::string& managerVersion, const std::string& agentVersion)
    {
        auto parseParts = [](const std::string& v) -> std::array<int, 2>
        {
            std::array<int, 2> parts {0, 0};
            std::string version = v;
            if (!version.empty() && (version[0] == 'v' || version[0] == 'V'))
            {
                version = version.substr(1);
            }
            const size_t pos = version.find_first_of("+-");
            std::string numericPart = (pos != std::string::npos) ? version.substr(0, pos) : version;

            std::istringstream iss(numericPart);
            std::string token;
            int i = 0;
            while (std::getline(iss, token, '.') && i < static_cast<int>(parts.size()))
            {
                try
                {
                    parts[i++] = std::stoi(token);
                }
                catch (...)
                {
                    break;
                }
            }
            return parts;
        };

        const auto m = parseParts(managerVersion);
        const auto a = parseParts(agentVersion);
        return a[0] > m[0] || (a[0] == m[0] && a[1] > m[1]);
    }

    struct Task
    {
        std::string id;
        std::string type;
        nlohmann::json payload;
    };

    enum class AgentStatusCode : int
    {
        Ok = 0,
        InvalidVersion = 1,
        ErrVersionRecv = 2,
        HcShutdownRecv = 3,
    };

    struct HttpResponse
    {
        int status;
        std::string body;
    };

    using ResponseCallback = std::function<void(const HttpResponse&)>;

} // namespace remoted::control

#endif // _REMOTED_CONTROL_TYPES_HPP
