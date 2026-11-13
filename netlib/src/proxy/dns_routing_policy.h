#pragma once

// Global DNS routing policy used by socks_local_router's packet handlers.
//
// Everything in this header is deliberately free of Windows, driver, and socket types so the
// routing decisions, the DNS server override syntax, and the parsing the DNS relay relies on
// can be unit tested on any platform without the Windows Packet Filter driver. The router
// supplies already-parsed packet fields and the state of the selected proxy; these helpers
// return what to do with the packet.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace proxy
{
    /// Conventional DNS destination port. Only this port is classified as DNS; payloads are
    /// never inspected to classify traffic.
    inline constexpr uint16_t dns_port = 53;

    /// Global DNS routing mode.
    enum class dns_routing_mode : uint8_t
    {
        /// UDP/TCP traffic to port 53 bypasses every SOCKS5 proxy (default).
        direct,
        /// UDP/TCP traffic to port 53 is sent through one selected SOCKS5 proxy, or dropped.
        proxy
    };

    /// What a packet handler does with a packet addressed to a destination port.
    enum class dns_route_action : uint8_t
    {
        not_dns, ///< not conventional DNS: continue with the ordinary application routing
        pass,    ///< DNS that stays direct
        proxy,   ///< redirect to the selected proxy's local listener (dns_route_decision::listener_port)
        block,   ///< DNS that must use the proxy but cannot: drop it, never send it direct
        defer    ///< addressed to a SOCKS5 server and its sender is not known yet: resolve it later
    };

    /// Why Proxy mode blocked a DNS packet; used for throttled diagnostics.
    enum class dns_block_reason : uint8_t
    {
        none,
        proxy_unavailable,        ///< no usable proxy was selected (invalid reference or creation failure)
        transport_unsupported,    ///< the selected proxy does not carry this transport (TCP or UDP)
        family_unsupported,       ///< the selected proxy does not accept destinations of this family
        listener_unavailable,     ///< the local listener for this transport and family is not running
        override_family_mismatch, ///< a server override of the other address family is configured
        redirect_failed,          ///< the packet could not be redirected (e.g. fragmented, oversized,
                                  ///< or a TCP segment of a connection opened before ProxiFyre started)
        upstream_sender_unknown,  ///< addressed to a SOCKS5 server, and its sender could not be resolved
        fragmented,               ///< the first fragment of a fragmented datagram addressed to port 53
        not_dns_message,          ///< a UDP datagram too short for a DNS header: it cannot be relayed
        count
    };

    /// Transport of the packet being classified.
    enum class dns_transport : uint8_t { tcp, udp };

    /// Address family of the packet being classified.
    enum class dns_family : uint8_t { ipv4, ipv6 };

    struct dns_route_decision
    {
        dns_route_action action{ dns_route_action::not_dns };
        dns_block_reason reason{ dns_block_reason::none };
        uint16_t listener_port{}; ///< local listener (host byte order) when action == proxy
    };

    /// What the selected DNS proxy offers to the transport and family being routed.
    struct dns_proxy_target
    {
        bool selected{};                     ///< a valid proxy is selected for DNS
        bool transport_supported{};          ///< it carries this transport
        bool family_supported{};             ///< it accepts destinations of this family
        std::optional<uint16_t> listener_port; ///< its local listener for this transport and family
        bool override_configured{};          ///< a DNS server override is configured
        bool override_family_matches{};      ///< the override has the family of this packet
    };

    /// Outcome of the recursion guard for a port-53 packet in Proxy mode.
    enum class dns_upstream_guard : uint8_t
    {
        apply_policy, ///< not ProxiFyre's own traffic to a SOCKS5 server: apply the DNS policy
        exempt,       ///< ProxiFyre's own traffic to one of its SOCKS5 servers: pass it
        defer,        ///< addressed to a SOCKS5 server, sender not resolved yet: resolve it later
        drop          ///< addressed to a SOCKS5 server, sender still unresolved: drop it
    };

    /**
     * @brief The recursion guard: keeps ProxiFyre's own SOCKS5 traffic out of the DNS proxy.
     *
     * Matching the destination against the configured SOCKS5 servers is only a cheap pre-filter.
     * A host can be both the SOCKS5 server and a resolver, so a packet addressed to it is exempt
     * only when its sender is ProxiFyre itself; anyone else's query to that host is subject to
     * the DNS policy like any other. When the sender cannot be determined inline the packet is
     * deferred to the resolver thread; if it is still unknown there it is dropped: passing it
     * could leak a query, and redirecting ProxiFyre's own traffic would loop.
     *
     * @param destination_matches_upstream The destination is a configured SOCKS5 server (UDP: its
     *        address; TCP: its address and port).
     * @param sender_is_proxifyre Whether the resolved owner is ProxiFyre's own process; nullopt
     *        when the owner is not resolved. Only consulted when the destination matches.
     * @param sender_lookup_final The lookup used a refreshed connection table (deferred path).
     */
    [[nodiscard]] constexpr dns_upstream_guard decide_dns_upstream_guard(
        const bool destination_matches_upstream,
        const std::optional<bool> sender_is_proxifyre,
        const bool sender_lookup_final) noexcept
    {
        if (!destination_matches_upstream)
            return dns_upstream_guard::apply_policy;
        if (sender_is_proxifyre)
            return *sender_is_proxifyre ? dns_upstream_guard::exempt : dns_upstream_guard::apply_policy;
        return sender_lookup_final ? dns_upstream_guard::drop : dns_upstream_guard::defer;
    }

    /**
     * @brief Whether a port-53 packet addressed to a configured SOCKS5 server can be ProxiFyre's
     *        own traffic, and so needs the sender check of decide_dns_upstream_guard().
     *
     * ProxiFyre's TCP traffic to a SOCKS5 server goes to its configured port, so for TCP the
     * destination match (address and port 53) already implies a server configured on port 53.
     * The only ProxiFyre UDP traffic to a SOCKS5 server's address that can reach the recursion
     * guard goes to relay endpoints returned by UDP ASSOCIATE, for the per-port UDP proxy and
     * for the DNS relay's shared association alike (the local listeners' replies, which can also
     * be addressed to a SOCKS5 host, are handled as listener replies before any DNS decision),
     * so for UDP the packet can be ProxiFyre's own only if a server has returned a relay on
     * port 53. Otherwise it cannot be, and it follows the DNS policy
     * with no sender lookup and no deferral, which also removes any dependence on the cached
     * connection table.
     *
     * @param udp_relay_on_dns_port A SOCKS5 server has returned a UDP relay endpoint on port 53.
     * @param destination_matches_upstream The destination is a configured SOCKS5 server (UDP: its
     *        address; TCP: its address and port).
     */
    [[nodiscard]] constexpr bool is_upstream_exemption_candidate(const dns_transport transport,
        const bool udp_relay_on_dns_port, const bool destination_matches_upstream) noexcept
    {
        return destination_matches_upstream && (transport == dns_transport::tcp || udp_relay_on_dns_port);
    }

    /**
     * @brief Decides how a captured outbound packet addressed to @p destination_port is routed.
     *
     * Apart from the recursion guard (see decide_dns_upstream_guard()), the decision depends
     * only on the destination port, the global mode, and the selected proxy. It does not depend
     * on the process that sent the packet, so traffic from the Windows DNS Client service
     * (svchost.exe) and from applications with their own resolvers is treated identically,
     * independently of application rules and exclusions.
     *
     * @param guard The recursion guard's outcome for this packet (apply_policy when the
     *        destination is not a SOCKS5 server).
     */
    [[nodiscard]] constexpr dns_route_decision decide_dns_route(
        const dns_routing_mode mode,
        const uint16_t destination_port,
        const dns_upstream_guard guard,
        const dns_proxy_target& target) noexcept
    {
        if (destination_port != dns_port)
            return { dns_route_action::not_dns, dns_block_reason::none, 0 };

        if (mode == dns_routing_mode::direct || guard == dns_upstream_guard::exempt)
            return { dns_route_action::pass, dns_block_reason::none, 0 };

        const auto block = [](const dns_block_reason reason) constexpr
        {
            return dns_route_decision{ dns_route_action::block, reason, 0 };
        };

        if (guard == dns_upstream_guard::defer)
            return { dns_route_action::defer, dns_block_reason::none, 0 };
        if (guard == dns_upstream_guard::drop)
            return block(dns_block_reason::upstream_sender_unknown);

        if (!target.selected)
            return block(dns_block_reason::proxy_unavailable);
        if (!target.transport_supported)
            return block(dns_block_reason::transport_unsupported);
        if (target.override_configured && !target.override_family_matches)
            return block(dns_block_reason::override_family_mismatch);
        if (!target.family_supported)
            return block(dns_block_reason::family_unsupported);
        if (!target.listener_port || *target.listener_port == 0)
            return block(dns_block_reason::listener_unavailable);

        return { dns_route_action::proxy, dns_block_reason::none, *target.listener_port };
    }

    /// Human-readable text for a block reason (diagnostics only).
    [[nodiscard]] constexpr const char* to_string(const dns_block_reason reason) noexcept
    {
        switch (reason)
        {
        case dns_block_reason::proxy_unavailable:
            return "no usable SOCKS5 proxy is selected for DNS";
        case dns_block_reason::transport_unsupported:
            return "the DNS proxy does not support this transport";
        case dns_block_reason::family_unsupported:
            return "the DNS proxy does not support this destination address family";
        case dns_block_reason::listener_unavailable:
            return "the DNS proxy's local listener for this transport and address family is not available";
        case dns_block_reason::override_family_mismatch:
            return "the DNS server override belongs to the other address family";
        case dns_block_reason::redirect_failed:
            return "the packet could not be redirected to the DNS proxy (fragmented, oversized, "
                "or part of a TCP connection opened before ProxiFyre started)";
        case dns_block_reason::fragmented:
            return "the datagram is fragmented and cannot be redirected through the DNS proxy; only its first "
                "fragment, which carries the port, is dropped";
        case dns_block_reason::not_dns_message:
            return "the UDP datagram is too short to be a DNS message, so the DNS proxy cannot relay it";
        case dns_block_reason::upstream_sender_unknown:
            return "the packet is addressed to a configured SOCKS5 server and its sending process could not be "
                "resolved, so it cannot be identified as ProxiFyre's own traffic";
        default:
            return "unknown";
        }
    }

    // ---------------------------------------------------------------------------------------
    // Driver filters
    // ---------------------------------------------------------------------------------------

    /// Local listener ports (host byte order) of the DNS proxy; nullopt or 0 when not running.
    struct dns_listener_ports
    {
        std::optional<uint16_t> tcp4;
        std::optional<uint16_t> udp4;
        std::optional<uint16_t> tcp6;
        std::optional<uint16_t> udp6;
    };

    /// One outbound REDIRECT (to user mode) driver filter the DNS policy needs.
    struct dns_filter_spec
    {
        dns_family family{};
        dns_transport transport{};
        std::optional<uint16_t> destination_port; ///< host byte order
        std::optional<uint16_t> source_port;      ///< host byte order

        bool operator==(const dns_filter_spec&) const = default;
    };

    /**
     * @brief The driver filters the DNS policy installs for @p mode.
     *
     * Static PASS filters (LAN bypass, the SOCKS5 upstream exemptions) are evaluated in the
     * driver before the user-mode handler sees a packet. In Proxy mode, REDIRECT filters at the
     * front of the table keep outbound TCP/UDP to port 53, and the DNS proxy listeners' replies
     * (outbound from their ports and addressed to the original, often LAN, server), in user mode
     * for both address families. Direct mode needs none. A listener that is not running (no port
     * or port 0) gets no filter: a source-port filter for port 0 would be meaningless.
     */
    [[nodiscard]] inline std::vector<dns_filter_spec> plan_dns_filters(const dns_routing_mode mode,
        const dns_listener_ports& listeners)
    {
        std::vector<dns_filter_spec> plan;
        if (mode != dns_routing_mode::proxy)
            return plan;

        for (const auto family : { dns_family::ipv4, dns_family::ipv6 })
        {
            for (const auto transport : { dns_transport::udp, dns_transport::tcp })
                plan.push_back({ family, transport, dns_port, std::nullopt });
        }

        const auto add_listener = [&plan](const dns_family family, const dns_transport transport,
                                          const std::optional<uint16_t> port)
        {
            if (port && *port != 0)
                plan.push_back({ family, transport, std::nullopt, *port });
        };
        add_listener(dns_family::ipv4, dns_transport::tcp, listeners.tcp4);
        add_listener(dns_family::ipv4, dns_transport::udp, listeners.udp4);
        add_listener(dns_family::ipv6, dns_transport::tcp, listeners.tcp6);
        add_listener(dns_family::ipv6, dns_transport::udp, listeners.udp6);
        return plan;
    }

    // ---------------------------------------------------------------------------------------
    // Fragments
    //
    // Only the first fragment of a fragmented datagram carries the transport header, so only it
    // can be classified as DNS. Redirection rewrites single packets, so a fragmented DNS datagram
    // cannot be sent through the DNS proxy; in Proxy mode its first fragment is dropped, which
    // keeps the datagram from being reassembled at the real server. Later fragments carry no
    // ports and are left alone, so unrelated fragmented traffic is not affected.
    // ---------------------------------------------------------------------------------------

    /// Fragmentation state of an IPv4 packet.
    enum class ipv4_fragment : uint8_t
    {
        none,  ///< not fragmented
        first, ///< fragment offset 0 with More Fragments set: carries the transport header
        later  ///< non-zero fragment offset: no transport header, its "ports" are payload bytes
    };

    /// Classifies an IPv4 packet from its flags/fragment-offset field (host byte order).
    [[nodiscard]] constexpr ipv4_fragment classify_ipv4_fragment(const uint16_t flags_and_offset) noexcept
    {
        if ((flags_and_offset & 0x1fff) != 0)
            return ipv4_fragment::later;
        return (flags_and_offset & 0x2000) != 0 ? ipv4_fragment::first : ipv4_fragment::none;
    }

    /**
     * @brief Whether an IPv4 packet carries a transport header, so its "ports" are ports.
     *
     * A later fragment's first payload bytes are application data. Nothing that keys on ports,
     * neither the local-listener check nor DNS classification, may use them: a later fragment
     * of an unrelated datagram whose data happens to equal a listener port would otherwise be
     * dropped as an untranslatable listener reply. Later fragments are left to the ordinary
     * path and passed.
     */
    [[nodiscard]] constexpr bool ipv4_transport_header_present(const ipv4_fragment fragment) noexcept
    {
        return fragment != ipv4_fragment::later;
    }

    /**
     * @brief Whether a packet sourced from a local listener can be translated back to its client.
     *
     * A first fragment carries the listener's port but only part of the datagram or segment;
     * rewriting it alone would deliver a partial packet whose later fragments are not
     * translated. It is dropped and reported like any other untranslatable listener packet.
     * (The UDP redirect already rejects fragments; the TCP redirect does not check, so the TCP
     * handler applies this first.)
     */
    [[nodiscard]] constexpr bool ipv4_listener_packet_translatable(const ipv4_fragment fragment) noexcept
    {
        return fragment == ipv4_fragment::none;
    }

    /**
     * @brief Applies fragmentation to a DNS routing decision: a datagram that would be redirected
     *        but is fragmented cannot be, so it is blocked instead of being passed.
     */
    [[nodiscard]] constexpr dns_route_decision apply_fragmentation(const dns_route_decision decision,
        const bool first_fragment) noexcept
    {
        if (first_fragment && decision.action == dns_route_action::proxy)
            return { dns_route_action::block, dns_block_reason::fragmented, 0 };
        return decision;
    }

    /// Upper-layer protocol and destination port read from the first fragment of an IPv6 datagram.
    struct ipv6_first_fragment
    {
        uint8_t protocol{};          ///< IPPROTO_UDP (17) or IPPROTO_TCP (6)
        uint16_t destination_port{}; ///< host byte order
        uint16_t source_port{};      ///< host byte order
    };

    /**
     * @brief For an IPv6 packet that is the first fragment (offset 0) of a fragmented datagram
     *        whose upper-layer header is UDP or TCP, returns that protocol and its destination
     *        port.
     *
     * Walks the hop-by-hop, routing, and destination-options extension headers and the
     * fragment header. Returns std::nullopt for an unfragmented packet (the normal path handles
     * it), a later fragment (no ports), another upper-layer protocol, or a header chain that is
     * truncated within @p size bytes.
     *
     * @param ipv6_packet The IPv6 header followed by the captured payload.
     */
    [[nodiscard]] constexpr std::optional<ipv6_first_fragment> parse_ipv6_first_fragment(
        const uint8_t* ipv6_packet, const std::size_t size) noexcept
    {
        constexpr std::size_t ipv6_header_size = 40;
        constexpr uint8_t hop_by_hop = 0, tcp = 6, udp = 17, routing = 43, fragment = 44, destination_options = 60;

        if (ipv6_packet == nullptr || size < ipv6_header_size || (ipv6_packet[0] >> 4) != 6)
            return std::nullopt;

        uint8_t next = ipv6_packet[6];
        std::size_t offset = ipv6_header_size;
        bool fragmented = false;

        // A bound on the chain length keeps a malformed chain from looping.
        for (int headers = 0; headers < 16; ++headers)
        {
            if (next == hop_by_hop || next == routing || next == destination_options)
            {
                if (offset + 2 > size)
                    return std::nullopt;
                const auto length = (static_cast<std::size_t>(ipv6_packet[offset + 1]) + 1) * 8;
                next = ipv6_packet[offset];
                offset += length;
                continue;
            }

            if (next == fragment)
            {
                if (fragmented || offset + 8 > size)
                    return std::nullopt;
                const auto offset_and_flags = static_cast<uint16_t>((ipv6_packet[offset + 2] << 8) | ipv6_packet[offset + 3]);
                if ((offset_and_flags >> 3) != 0)
                    return std::nullopt; // a later fragment: no upper-layer header
                fragmented = true;
                next = ipv6_packet[offset];
                offset += 8;
                continue;
            }

            if (!fragmented || (next != udp && next != tcp) || offset + 4 > size)
                return std::nullopt;

            return ipv6_first_fragment{ next,
                static_cast<uint16_t>((ipv6_packet[offset + 2] << 8) | ipv6_packet[offset + 3]),
                static_cast<uint16_t>((ipv6_packet[offset] << 8) | ipv6_packet[offset + 1]) };
        }

        return std::nullopt;
    }

    /// What a packet handler does with an outbound packet whose source port is the port of one of
    /// ProxiFyre's local proxy listeners.
    enum class listener_reply_action : uint8_t
    {
        revert, ///< translated back to the original server/client: re-inject it to the stack
        drop    ///< not translatable: drop it
    };

    /**
     * @brief Decides what to do with a packet sourced from a local proxy listener.
     *
     * A listener reply is addressed to the original server only because redirection swapped the
     * addresses; it never belongs on the wire. When it cannot be translated back (no tracked
     * connection or endpoint, a fragmented or malformed datagram, a relay header of the wrong
     * address type), passing it would send the listener's bytes - for the DNS proxy, the SOCKS5
     * header and the DNS answer - toward the real server in clear, so it is dropped.
     *
     * @param translated The redirect translated the packet back to its client.
     */
    [[nodiscard]] constexpr listener_reply_action decide_listener_reply(const bool translated) noexcept
    {
        return translated ? listener_reply_action::revert : listener_reply_action::drop;
    }

    /// What tcp_local_redirect reported for a segment from a local TCP listener.
    enum class listener_segment_outcome : uint8_t
    {
        translated,     ///< rewritten for the client
        recently_reset, ///< belongs to a connection the client or the proxy just aborted with RST
        unknown         ///< belongs to no known connection
    };

    /// What a handler does with a segment from a local TCP listener.
    enum class listener_segment_action : uint8_t
    {
        revert,        ///< re-inject the translated segment to the client
        drop_quietly,  ///< drop it; an expected part of an abort, counted at debug level only
        drop_reported  ///< drop it and report it as an untranslatable listener reply
    };

    /**
     * @brief Decides what to do with a segment from a local TCP listener.
     *
     * When a connection is aborted with RST while the local proxy is still sending, the segments
     * the proxy emitted before its stack saw the RST arrive after the redirect has ended the
     * connection. They are dropped like any untranslatable listener segment (they must never reach
     * the wire), but they are an expected part of an abort, so they are not reported as faults.
     */
    [[nodiscard]] constexpr listener_segment_action decide_tcp_listener_segment(
        const listener_segment_outcome outcome) noexcept
    {
        switch (outcome)
        {
        case listener_segment_outcome::translated:
            return listener_segment_action::revert;
        case listener_segment_outcome::recently_reset:
            return listener_segment_action::drop_quietly;
        case listener_segment_outcome::unknown:
            break;
        }
        return listener_segment_action::drop_reported;
    }

    /// What the IPv6 handler does with a packet that has no usable transport header.
    enum class ipv6_fragment_action : uint8_t
    {
        pass,                ///< not classifiable, or nothing to enforce: pass it (existing behaviour)
        drop_listener_reply, ///< first fragment of a local listener's reply: never send it to the wire
        drop_dns             ///< first fragment of a DNS datagram in Proxy mode: never send it direct
    };

    /**
     * @brief Whether decide_ipv6_fragment() needs the DNS mode for @p first, so the caller reads
     *        the mode (which takes the router's lock) only for a first fragment that is not a
     *        listener reply and is addressed to port 53.
     */
    [[nodiscard]] constexpr bool ipv6_fragment_needs_dns_mode(const std::optional<ipv6_first_fragment>& first,
        const bool source_is_listener) noexcept
    {
        return first.has_value() && !source_is_listener && first->destination_port == dns_port;
    }

    /**
     * @brief Decides what to do with an IPv6 packet whose transport header cannot be used
     *        (a fragment, or an unsupported extension chain).
     *
     * A large listener reply (for example a DNS answer over about 1430 bytes) is fragmented by
     * the stack, so its first fragment carries the SOCKS5 header and the start of the answer.
     * It cannot be translated, so it is dropped in every mode, like an unfragmented listener
     * reply that cannot be translated. In Proxy mode the first fragment of a datagram addressed
     * to port 53 is dropped so DNS is never sent directly. Everything else, including later
     * fragments, which carry no ports, is passed as before.
     *
     * @param first The parsed first fragment (parse_ipv6_first_fragment()), or nullopt.
     * @param source_is_listener The first fragment's source port is a local IPv6 proxy listener
     *        port of its protocol.
     */
    [[nodiscard]] constexpr ipv6_fragment_action decide_ipv6_fragment(const std::optional<ipv6_first_fragment>& first,
        const bool source_is_listener, const bool dns_proxy_mode) noexcept
    {
        if (!first)
            return ipv6_fragment_action::pass;
        if (source_is_listener)
            return ipv6_fragment_action::drop_listener_reply;
        if (dns_proxy_mode && first->destination_port == dns_port)
            return ipv6_fragment_action::drop_dns;
        return ipv6_fragment_action::pass;
    }

    /// A DNS server override split into its literal address text and port.
    struct dns_server_override_text
    {
        std::string address; ///< IPv4 or IPv6 literal text (brackets removed), not yet validated
        uint16_t port{ dns_port };
        bool bracketed{};    ///< written as [address] or [address]:port
    };

    /**
     * @brief Splits a DNS server override into address text and port without resolving names.
     *
     * Accepted forms: "1.1.1.1", "1.1.1.1:5353", "2606:4700:4700::1111",
     * "[2606:4700:4700::1111]" and "[2606:4700:4700::1111]:5353". An unbracketed value
     * containing more than one ':' is an IPv6 literal without a port. Whether the address
     * text is a valid literal of the expected family is checked by the caller.
     */
    [[nodiscard]] inline std::optional<dns_server_override_text> split_dns_server_override(std::string_view value)
    {
        const auto is_space = [](const char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
        while (!value.empty() && is_space(value.front()))
            value.remove_prefix(1);
        while (!value.empty() && is_space(value.back()))
            value.remove_suffix(1);

        if (value.empty())
            return std::nullopt;

        const auto parse_port = [](const std::string_view text) -> std::optional<uint16_t>
        {
            if (text.empty() || text.size() > 5)
                return std::nullopt;
            uint32_t port = 0;
            for (const auto c : text)
            {
                if (c < '0' || c > '9')
                    return std::nullopt;
                port = port * 10 + static_cast<uint32_t>(c - '0');
            }
            if (port == 0 || port > 65535)
                return std::nullopt;
            return static_cast<uint16_t>(port);
        };

        dns_server_override_text result;

        if (value.front() == '[')
        {
            const auto closing = value.find(']');
            if (closing == std::string_view::npos || closing == 1)
                return std::nullopt;

            result.address = std::string{ value.substr(1, closing - 1) };
            result.bracketed = true;

            const auto rest = value.substr(closing + 1);
            if (!rest.empty())
            {
                if (rest.front() != ':')
                    return std::nullopt;
                const auto port = parse_port(rest.substr(1));
                if (!port)
                    return std::nullopt;
                result.port = *port;
            }
        }
        else
        {
            const auto first_colon = value.find(':');
            if (first_colon == std::string_view::npos)
            {
                result.address = std::string{ value };
            }
            else if (value.find(':', first_colon + 1) == std::string_view::npos)
            {
                // Exactly one colon: IPv4 literal with a port.
                const auto port = parse_port(value.substr(first_colon + 1));
                if (!port || first_colon == 0)
                    return std::nullopt;
                result.address = std::string{ value.substr(0, first_colon) };
                result.port = *port;
            }
            else
            {
                // Several colons and no brackets: an IPv6 literal without a port.
                result.address = std::string{ value };
            }
        }

        if (result.address.empty() ||
            std::any_of(result.address.begin(), result.address.end(),
                [&](const char c) { return is_space(c) || c == '[' || c == ']' || c == '/' || c == '\\' || c == '%'; }))
            return std::nullopt;

        return result;
    }

    /// Minimum size of a DNS message header (RFC 1035 section 4.1.1).
    inline constexpr std::size_t dns_header_size = 12;

    /// Reads the DNS message ID used to map answers back to the server the resolver queried.
    /// The payload is not used to classify traffic: classification is by port 53 only.
    [[nodiscard]] constexpr std::optional<uint16_t> dns_message_id(const uint8_t* payload, const std::size_t size) noexcept
    {
        if (payload == nullptr || size < dns_header_size)
            return std::nullopt;
        return static_cast<uint16_t>((static_cast<uint16_t>(payload[0]) << 8) | payload[1]);
    }

    /// SOCKS5 UDP request/reply header fields (RFC 1928 section 7) of a relayed datagram.
    struct socks5_udp_datagram_view
    {
        uint8_t address_type{};          ///< ATYP: 1 = IPv4, 4 = IPv6
        const uint8_t* address{};        ///< DST.ADDR (network byte order)
        std::size_t address_size{};      ///< 4 or 16
        uint16_t port{};                 ///< DST.PORT (host byte order)
        const uint8_t* data{};           ///< DATA following the header
        std::size_t data_size{};
    };

    /**
     * @brief Parses the SOCKS5 UDP header of a datagram relayed by a SOCKS5 server.
     * @return std::nullopt for a short buffer, a non-zero RSV or FRAG field, or an address type
     *         other than IPv4/IPv6 literals.
     */
    [[nodiscard]] constexpr std::optional<socks5_udp_datagram_view> parse_socks5_udp_datagram(
        const uint8_t* datagram, const std::size_t size) noexcept
    {
        if (datagram == nullptr || size < 4 || datagram[0] != 0 || datagram[1] != 0 || datagram[2] != 0)
            return std::nullopt;

        socks5_udp_datagram_view view;
        view.address_type = datagram[3];
        if (view.address_type == 1)
            view.address_size = 4;
        else if (view.address_type == 4)
            view.address_size = 16;
        else
            return std::nullopt;

        const auto header_size = 4 + view.address_size + 2;
        if (size < header_size)
            return std::nullopt;

        view.address = datagram + 4;
        view.port = static_cast<uint16_t>((static_cast<uint16_t>(datagram[4 + view.address_size]) << 8) |
            datagram[4 + view.address_size + 1]);
        view.data = datagram + header_size;
        view.data_size = size - header_size;
        return view;
    }

    // Compile-time checks of the decision table's key invariants.
    static_assert(decide_listener_reply(false) == listener_reply_action::drop,
        "An untranslatable listener reply must never be passed to the wire.");
    static_assert(decide_dns_route(dns_routing_mode::direct, 443, dns_upstream_guard::apply_policy, {}).action ==
        dns_route_action::not_dns, "Non-DNS traffic must keep its ordinary routing.");
    static_assert(decide_dns_route(dns_routing_mode::direct, dns_port, dns_upstream_guard::apply_policy, {}).action ==
        dns_route_action::pass, "Direct mode must pass DNS without consulting a proxy.");
    static_assert(decide_dns_route(dns_routing_mode::proxy, dns_port, dns_upstream_guard::apply_policy, {}).action ==
        dns_route_action::block, "Proxy mode without a usable proxy must fail closed.");
    static_assert(decide_dns_route(dns_routing_mode::proxy, dns_port, dns_upstream_guard::exempt, {}).action ==
        dns_route_action::pass, "ProxiFyre's own upstream traffic must never be captured recursively.");
    static_assert(decide_dns_upstream_guard(true, std::nullopt, true) == dns_upstream_guard::drop,
        "Unattributed traffic to a SOCKS5 server must be neither passed nor redirected.");
}
