#pragma once

namespace proxy
{
    /**
     * @brief Returns true when an unresolved process owner must remain direct.
     *
     * Keeping this policy as a small pure function makes the limited-mode safety
     * invariant independently testable without constructing the packet filter or
     * opening the Windows Packet Filter driver.
     */
    [[nodiscard]] constexpr bool should_bypass_unresolved_process(
        const bool bypass_unresolved_processes,
        const bool process_resolved) noexcept
    {
        return bypass_unresolved_processes && !process_resolved;
    }

    static_assert(!should_bypass_unresolved_process(false, false),
        "Normal mode must preserve routing for unresolved owners.");
    static_assert(!should_bypass_unresolved_process(false, true),
        "Normal mode must preserve routing for resolved owners.");
    static_assert(should_bypass_unresolved_process(true, false),
        "Limited mode must keep unresolved-owner traffic direct.");
    static_assert(!should_bypass_unresolved_process(true, true),
        "Limited mode must keep resolved-owner traffic eligible for matching.");

    // ------------------------------------------------------------------------------------------
    // Owner routing decisions used by socks_local_router's packet handlers. They read and update
    // the routing state cached on an iphelper::network_process (declared in process_lookup.h,
    // which the product and test PCHs include first). Like should_bypass_unresolved_process,
    // they are kept here so the decisions can be exercised without the packet filter driver.
    // ------------------------------------------------------------------------------------------

    /// What a packet handler does with an owner's packet.
    enum class proxy_port_action : uint8_t
    {
        none,   ///< not proxied: pass the packet
        proxy,  ///< redirect to the local proxy listener in proxy_port_result::port
        block   ///< matched, but the selected proxy cannot carry it: drop the packet
    };

    struct proxy_port_result
    {
        proxy_port_action action{ proxy_port_action::none };
        uint16_t port{};  // NOLINT(clang-diagnostic-padded)
    };

    /// Transport whose cached owner state (bypass flag, optional proxy port) a decision uses.
    enum class owner_transport : uint8_t { tcp, udp };

    /// Address family of the packet handler making a decision.
    enum class owner_family : uint8_t { ipv4, ipv6 };

    /// The router's application matching configuration (non-owning).
    struct owner_match_rules
    {
        const std::multimap<size_t, std::wstring>& proxy_to_names;  ///< proxy index -> app pattern
        const std::vector<std::wstring>& excluded_list;             ///< upper-cased exclusion entries
        bool bypass_unresolved_processes;                           ///< limited/unelevated mode
        unsigned long current_process_id;                           ///< never matched
    };

    /// What one configured proxy offers to the transport and address family being routed.
    struct proxy_route_target
    {
        bool transport_supported{};             ///< the proxy carries this transport
        bool family_supported{};                ///< the proxy accepts destinations of this family
        std::optional<uint16_t> listener_port;  ///< local listener for this transport and family
    };

    /**
     * @brief Records the association socks_local_router::associate_process_name_to_proxy makes:
     *        @p proxy_id -> the upper-cased @p process_name pattern, appended after the patterns
     *        already configured (select_proxy_port() takes the first match).
     *
     * The caller holds the router's configuration lock. The association applies to every owner
     * routed afterwards; an owner object that already cached a bypass decision for a transport
     * keeps it until the next capture replaces it (see route_owner()).
     *
     * @param proxy_count Number of configured proxies; an index at or beyond it is rejected.
     * @return false when @p proxy_id is out of range (nothing is changed).
     * @throws std::bad_alloc from the container insertion.
     */
    [[nodiscard]] inline bool associate_process_name_pattern(std::multimap<size_t, std::wstring>& proxy_to_names,
        const size_t proxy_id, const size_t proxy_count, const std::wstring& process_name)
    {
        if (proxy_id >= proxy_count)
            return false;

        proxy_to_names.emplace(proxy_id, iphelper::network_process::to_upper(process_name));
        return true;
    }

    /**
     * @brief Matches an application name pattern against the process details with exclusion support.
     *
     * Matching semantics:
     *   - A NAME entry (no path separator) matches the process's bare name ANCHORED to the
     *     whole filename: an exact match, or the entry as the filename stem immediately followed
     *     by '.' (so a short pattern like "NOTE" does not match "EVILNOTE.EXE").
     *   - A PATH entry (contains '/' or '\\') matches as a SUBSTRING against the full path.
     *   - An EMPTY entry ("") is the CATCH-ALL: it matches ANY process not in the exclusion list.
     *   - Exclusion entries match as SUBSTRINGS of the name (or of the full path for path-form
     *     entries); a process matching one is marked excluded and never matches.
     * Comparisons are effectively case-insensitive because inputs are already upper-cased by the
     * caller. The current process (by PID) never matches, and in limited mode neither does an
     * unresolved owner.
     *
     * @param app The upper-cased application name or pattern.
     * @param process The owner to check; its excluded flag is set when an exclusion matches.
     * @param rules The router's exclusion list, limited-mode flag, and current process ID.
     * @return true if the process matches @p app and is neither excluded nor the current process.
     */
    [[nodiscard]] inline bool match_owner_to_app(const std::wstring& app, iphelper::network_process& process,
        const owner_match_rules& rules)
    {
        // In explicitly enabled limited/unelevated mode, process attribution is
        // best-effort. Never let an unresolved synthetic owner match either a named
        // application or the empty catch-all pattern; its traffic must remain direct.
        // The flag defaults to false, preserving the existing elevated/service behavior.
        if (should_bypass_unresolved_process(rules.bypass_unresolved_processes, process.resolved))
            return false;

        // Exclude the current process by process ID (not cached since it's a quick check)
        if (process.id == rules.current_process_id)
            return false;

        // Matches a configured executable name (one without a path separator) against the
        // process's bare name. Anchored to the whole filename -- an exact match, or the
        // entry as the filename stem immediately followed by an extension -- so a short
        // pattern can't match an unrelated process (e.g. "NOTE" matching "EVILNOTE.EXE").
        // Inputs are already uppercased by the caller. Path-form entries (containing a
        // separator) still use substring matching against the full path.
        const auto name_matches = [](const std::wstring& name, const std::wstring& entry)
        {
            if (entry.empty())
                return false;
            if (name == entry)
                return true;
            return name.size() > entry.size()
                && name.compare(0, entry.size(), entry) == 0
                && name[entry.size()] == L'.';
        };

        // Check exclusion list. Excludes use SUBSTRING matching for BOTH name and path forms.
        // An exclusion is a safety / bypass rule ("keep this app OUT of the proxy"), so it must
        // be permissive -- matching more processes rather than fewer -- to avoid accidentally
        // routing traffic the user meant to keep direct (a real risk when combined with a ""
        // catch-all proxy). This preserves the pre-v2.3.0 behavior; appName matching above stays
        // anchored (where being precise is the safe direction). An empty entry is ignored so it
        // cannot match every process.
        for (const auto& excluded_entry : rules.excluded_list) {
            if (!excluded_entry.empty() &&
                ((excluded_entry.find_first_of(L"\\/") != std::wstring::npos)
                    ? (process.path_name.find(excluded_entry) != std::wstring::npos)
                    : (process.name.find(excluded_entry) != std::wstring::npos))
                ) {
                process.excluded = true;
                return false; // Excluded
            }
        }

        // An empty app pattern is the catch-all: match ANY process not excluded above. This
        // restores the long-standing behavior (before matching was anchored) where a substring
        // find("") matched every process, letting an appNames entry of "" act as a default /
        // fallback proxy for all remaining traffic. Non-empty names keep the anchored matching
        // above (so a short pattern still can't match an unrelated process).
        if (app.empty())
            return true;

        return (app.find(L'\\') != std::wstring::npos || app.find(L'/') != std::wstring::npos)
                ? (process.path_name.find(app) != std::wstring::npos)
                : name_matches(process.name, app);
    }

    /**
     * @brief Selects the proxy for an owner: the first configured pattern that matches decides.
     *
     * @param target_of size_t proxy index -> proxy_route_target for the transport and family
     *        being routed.
     * @return proxy with the listener port; block when the matched proxy cannot carry the
     *         family or has no listener; none when nothing matches or the matched proxy does
     *         not carry the transport.
     */
    template <class TargetOf>
    [[nodiscard]] proxy_port_result select_proxy_port(const owner_match_rules& rules,
        iphelper::network_process& process, TargetOf&& target_of)
    {
        for (const auto& [proxy_id, process_pattern] : rules.proxy_to_names)
        {
            if (match_owner_to_app(process_pattern, process, rules))
            {
                const proxy_route_target target = target_of(proxy_id);

                if (!target.transport_supported)
                    return {};

                if (!target.family_supported)
                    return { proxy_port_action::block, 0 };

                if (target.listener_port)
                    return { proxy_port_action::proxy, target.listener_port.value() };

                return { proxy_port_action::block, 0 };
            }
        }

        return {};
    }

    /**
     * @brief The owner-level part of a packet handler's routing decision.
     *
     * An excluded owner, or one already known to bypass this transport, passes without a new
     * selection. Otherwise an IPv4 handler uses the owner's preassigned proxy port for the
     * transport when one is set (the IPv6 handlers do not consult it), and @p select decides.
     * A selection of none marks the owner as bypassing this transport.
     *
     * Each published connection-table row has its own owner object, so the cached state is
     * per connection: it is derived from the owner's identity and the proxy configuration at
     * the time of the decision and stays with that connection until the next capture publishes
     * a new owner object for it. Connections not yet routed are decided against the current
     * configuration.
     *
     * @param select () -> proxy_port_result, the proxy selection for this transport and family.
     * @return none: pass the packet; proxy: redirect to port; block: drop the packet.
     */
    template <owner_transport Transport, owner_family Family, class Select>
    [[nodiscard]] proxy_port_result route_owner(iphelper::network_process& process, Select&& select)
    {
        auto& bypass = Transport == owner_transport::tcp ? process.bypass_tcp : process.bypass_udp;

        if (process.excluded || bypass)
            return {};

        if constexpr (Family == owner_family::ipv4)
        {
            const auto& proxy_port = Transport == owner_transport::tcp
                ? process.tcp_proxy_port
                : process.udp_proxy_port;

            if (proxy_port)
                return { proxy_port_action::proxy, proxy_port.value() };
        }

        const proxy_port_result result = select();

        if (result.action == proxy_port_action::none)
            bypass = true;

        return result;
    }
}
