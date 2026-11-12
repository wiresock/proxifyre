#pragma once

// Global DNS routing policy used by socks_local_router's packet handlers.
//
// Everything in this header is deliberately free of Windows, driver, and socket types so the
// routing decisions, the DNS server override syntax, and the UDP response-origin bookkeeping
// can be unit tested on any platform without the Windows Packet Filter driver. The router
// supplies already-parsed packet fields and the state of the selected proxy; these helpers
// return what to do with the packet.

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
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
                "not a DNS message, or part of a TCP connection opened before ProxiFyre started)";
        case dns_block_reason::fragmented:
            return "the datagram is fragmented and cannot be redirected through the DNS proxy; only its first "
                "fragment, which carries the port, is dropped";
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
                static_cast<uint16_t>((ipv6_packet[offset + 2] << 8) | ipv6_packet[offset + 3]) };
        }

        return std::nullopt;
    }

    /// What a packet handler does with an outbound packet whose source port is the port of one of
    /// ProxiFyre's local proxy listeners.
    enum class listener_reply_action : uint8_t
    {
        not_listener, ///< not sourced from a local listener: continue with the normal routing
        revert,       ///< translated back to the original server/client: re-inject it to the stack
        drop          ///< not translatable: drop it
    };

    /**
     * @brief Decides what to do with a packet sourced from a local proxy listener.
     *
     * A listener reply is addressed to the original server only because redirection swapped the
     * addresses; it never belongs on the wire. When it cannot be translated back (no tracked
     * connection or endpoint, a fragmented or malformed datagram, a relay header of the wrong
     * address type), passing it would send the listener's bytes - for the DNS proxy, the SOCKS5
     * header and the DNS answer - toward the real server in clear, so it is dropped.
     */
    [[nodiscard]] constexpr listener_reply_action decide_listener_reply(
        const bool source_is_listener, const bool translated) noexcept
    {
        if (!source_is_listener)
            return listener_reply_action::not_listener;
        return translated ? listener_reply_action::revert : listener_reply_action::drop;
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

    /// Reads the DNS message ID used to map override responses back to their original server.
    /// The payload is not used to classify traffic: classification is by port 53 only.
    [[nodiscard]] constexpr std::optional<uint16_t> dns_message_id(const uint8_t* payload, const std::size_t size) noexcept
    {
        if (payload == nullptr || size < dns_header_size)
            return std::nullopt;
        return static_cast<uint16_t>((static_cast<uint16_t>(payload[0]) << 8) | payload[1]);
    }

    /**
     * @brief Remembers, for UDP DNS queries rewritten to a server override, which server the
     *        application originally addressed.
     *
     * When a server override is configured, the SOCKS5 relay answers from the override server
     * while the requesting resolver only accepts an answer from the server it queried. Each
     * rewritten query records (client source port, DNS message ID) -> original server endpoint;
     * the response carrying the same client port and message ID is restored to that endpoint
     * before it is delivered. Entries expire after @p ttl and the table is bounded, so it cannot
     * grow without limit under a flood of queries. Entries are not consumed by a lookup so that
     * duplicate answers to a retransmitted query are restored consistently.
     *
     * Thread-safe.
     *
     * @tparam Endpoint Original server endpoint type (copyable).
     */
    template <typename Endpoint>
    class dns_udp_origin_tracker
    {
    public:
        using clock = std::chrono::steady_clock;

        explicit dns_udp_origin_tracker(const std::chrono::seconds ttl = std::chrono::seconds{ 30 },
            const std::size_t capacity = 8192) noexcept
            : ttl_(ttl), capacity_(std::max<std::size_t>(capacity, 1))
        {
        }

        /**
         * @brief Records the original server of a query sent from @p client_port with
         *        @p message_id. Re-remembering a key refreshes its time.
         *
         * Runs on the packet thread, so it costs amortized O(1) even when the table is full of
         * live entries: expired and then oldest entries are found at the front of an
         * insertion-ordered queue instead of by scanning the table.
         */
        void remember(const uint16_t client_port, const uint16_t message_id, const Endpoint& original,
            const clock::time_point now = clock::now())
        {
            std::scoped_lock lock(lock_);
            const auto key = make_key(client_port, message_id);

            if (const auto it = entries_.find(key); it != entries_.end())
            {
                // The key's earlier queue record becomes stale; it is skipped when it reaches
                // the front.
                it->second = entry{ now, original };
                order_.push_back({ key, now });
                compact_if_needed_locked();
                return;
            }

            if (entries_.size() >= capacity_)
            {
                expire_front_locked(now);
                if (entries_.size() >= capacity_)
                    evict_oldest_locked();
            }

            entries_.emplace(key, entry{ now, original });
            order_.push_back({ key, now });
            compact_if_needed_locked();
        }

        /// Returns the original server for a response to @p client_port with @p message_id.
        [[nodiscard]] std::optional<Endpoint> resolve(const uint16_t client_port, const uint16_t message_id,
            const clock::time_point now = clock::now())
        {
            std::scoped_lock lock(lock_);
            const auto it = entries_.find(make_key(client_port, message_id));
            if (it == entries_.end())
                return std::nullopt;

            if (now - it->second.created_at > ttl_)
            {
                entries_.erase(it);
                return std::nullopt;
            }

            return it->second.original;
        }

        /// Removes every expired entry (maintenance thread).
        void sweep(const clock::time_point now = clock::now())
        {
            std::scoped_lock lock(lock_);
            for (auto it = entries_.begin(); it != entries_.end();)
            {
                if (now - it->second.created_at > ttl_)
                    it = entries_.erase(it);
                else
                    ++it;
            }
            expire_front_locked(now);
        }

        /// Removes every entry (router start).
        void clear()
        {
            std::scoped_lock lock(lock_);
            entries_.clear();
            order_.clear();
        }

        [[nodiscard]] std::size_t size() const
        {
            std::scoped_lock lock(lock_);
            return entries_.size();
        }

        /// Number of insertion-order records, including stale ones (bounded; for tests).
        [[nodiscard]] std::size_t order_records() const
        {
            std::scoped_lock lock(lock_);
            return order_.size();
        }

    private:
        struct entry
        {
            clock::time_point created_at;
            Endpoint original;
        };

        struct record
        {
            uint32_t key;
            clock::time_point created_at;
        };

        static constexpr uint32_t make_key(const uint16_t client_port, const uint16_t message_id) noexcept
        {
            return (static_cast<uint32_t>(client_port) << 16) | message_id;
        }

        /// True when @p r is the current record of a live entry.
        [[nodiscard]] bool is_current_locked(const record& r) const
        {
            const auto it = entries_.find(r.key);
            return it != entries_.end() && it->second.created_at == r.created_at;
        }

        /// Pops expired records from the front, erasing the entries they still describe.
        void expire_front_locked(const clock::time_point now)
        {
            while (!order_.empty() && now - order_.front().created_at > ttl_)
            {
                if (is_current_locked(order_.front()))
                    entries_.erase(order_.front().key);
                order_.pop_front();
            }
        }

        /// Erases the oldest live entry, skipping stale records.
        void evict_oldest_locked()
        {
            while (!order_.empty())
            {
                const auto front = order_.front();
                order_.pop_front();
                if (is_current_locked(front))
                {
                    entries_.erase(front.key);
                    return;
                }
            }
        }

        /// Keeps the queue bounded when keys are refreshed repeatedly: rebuilds it from the
        /// live entries, oldest first, once stale records outnumber them.
        void compact_if_needed_locked()
        {
            if (order_.size() <= 2 * capacity_ + 16)
                return;

            std::vector<record> live;
            live.reserve(entries_.size());
            for (const auto& [key, value] : entries_)
                live.push_back({ key, value.created_at });
            std::sort(live.begin(), live.end(),
                [](const record& left, const record& right) { return left.created_at < right.created_at; });
            order_.assign(live.begin(), live.end());
        }

        mutable std::mutex lock_;
        std::unordered_map<uint32_t, entry> entries_;
        std::deque<record> order_;
        std::chrono::seconds ttl_;
        std::size_t capacity_;
    };

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

    /**
     * @brief Whether replies leaving the DNS proxy's UDP listener may need their source restored
     *        (classify_dns_override_reply()): only in Proxy mode with a usable proxy and a server
     *        override. Otherwise the reply path needs no DNS work at all.
     */
    [[nodiscard]] constexpr bool dns_reply_restore_needed(const dns_routing_mode mode, const bool proxy_selected,
        const bool server_override_configured) noexcept
    {
        return mode == dns_routing_mode::proxy && proxy_selected && server_override_configured;
    }

    /// How a datagram leaving a local UDP proxy listener is presented to the client.
    enum class dns_reply_restore : uint8_t
    {
        unchanged, ///< not an answer to a tracked query: present the relay's SOCKS5 header source
        restore,   ///< answer to a tracked query: present it as coming from the original server
        drop       ///< names the override server but answers no tracked query: drop it
    };

    /**
     * @brief Classifies a datagram relayed back by the DNS proxy while a server override is
     *        configured, and finds the server the resolver originally queried.
     *
     * A datagram whose (@p client_port, DNS message ID) matches a tracked query is restored to
     * the original server whatever source its SOCKS5 header reports: RFC 1928 relays report the
     * override server, but some report another address (for example their own), and an answer
     * presented from any address other than the queried server is discarded by the resolver.
     * A datagram that names the override server but matches no tracked query is dropped. Any
     * other datagram relayed through the same proxy is left unchanged.
     *
     * The datagram's ATYP must match the listener's family (@p expected_address_type): the
     * redirect strips a header of that family's size.
     *
     * @param socks_datagram The UDP payload as relayed: SOCKS5 UDP header followed by the data.
     * @param expected_address_type 1 for the IPv4 path, 4 for the IPv6 path.
     * @param override_address The override address bytes (network byte order).
     */
    template <typename Endpoint>
    [[nodiscard]] std::pair<dns_reply_restore, std::optional<Endpoint>> classify_dns_override_reply(
        const uint8_t* socks_datagram, const std::size_t size, const uint8_t expected_address_type,
        const uint8_t* override_address, const std::size_t override_address_size, const uint16_t override_port,
        const uint16_t client_port, dns_udp_origin_tracker<Endpoint>& origins)
    {
        const auto view = parse_socks5_udp_datagram(socks_datagram, size);
        if (!view || view->address_type != expected_address_type)
            return { dns_reply_restore::unchanged, std::nullopt };

        if (const auto message_id = dns_message_id(view->data, view->data_size))
        {
            if (auto original = origins.resolve(client_port, *message_id))
                return { dns_reply_restore::restore, std::move(original) };
        }

        const bool names_override = view->address_size == override_address_size && view->port == override_port &&
            std::equal(view->address, view->address + view->address_size, override_address);

        return { names_override ? dns_reply_restore::drop : dns_reply_restore::unchanged, std::nullopt };
    }

    // Compile-time checks of the decision table's key invariants.
    static_assert(decide_listener_reply(true, false) == listener_reply_action::drop,
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
