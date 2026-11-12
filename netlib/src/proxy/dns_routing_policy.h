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
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

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
        block    ///< DNS that must use the proxy but cannot: drop it, never send it direct
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

    /**
     * @brief Decides how a captured outbound packet addressed to @p destination_port is routed.
     *
     * The decision depends only on the destination port, the global mode, and the selected
     * proxy. It never depends on the process that sent the packet, so traffic from the Windows
     * DNS Client service (svchost.exe) and from applications with their own resolvers is
     * treated identically, independently of application rules and exclusions.
     *
     * @param destination_is_upstream The packet is addressed to one of ProxiFyre's own SOCKS5
     *        upstream servers (recursion guard: ProxiFyre's own proxy traffic is never captured).
     */
    [[nodiscard]] constexpr dns_route_decision decide_dns_route(
        const dns_routing_mode mode,
        const uint16_t destination_port,
        const bool destination_is_upstream,
        const dns_proxy_target& target) noexcept
    {
        if (destination_port != dns_port)
            return { dns_route_action::not_dns, dns_block_reason::none, 0 };

        if (mode == dns_routing_mode::direct || destination_is_upstream)
            return { dns_route_action::pass, dns_block_reason::none, 0 };

        const auto block = [](const dns_block_reason reason) constexpr
        {
            return dns_route_decision{ dns_route_action::block, reason, 0 };
        };

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
        default:
            return "unknown";
        }
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

        /// Records the original server of a query sent from @p client_port with @p message_id.
        void remember(const uint16_t client_port, const uint16_t message_id, const Endpoint& original,
            const clock::time_point now = clock::now())
        {
            std::scoped_lock lock(lock_);
            const auto key = make_key(client_port, message_id);

            if (const auto it = entries_.find(key); it != entries_.end())
            {
                it->second = entry{ now, original };
                return;
            }

            if (entries_.size() >= capacity_)
            {
                sweep_locked(now);
                if (entries_.size() >= capacity_)
                {
                    // Still full of live entries: evict the oldest one. Linear, but only reached
                    // when more than `capacity_` queries are outstanding within one TTL.
                    const auto oldest = std::min_element(entries_.begin(), entries_.end(),
                        [](const auto& left, const auto& right) { return left.second.created_at < right.second.created_at; });
                    entries_.erase(oldest);
                }
            }

            entries_.emplace(key, entry{ now, original });
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

        /// Removes expired entries.
        void sweep(const clock::time_point now = clock::now())
        {
            std::scoped_lock lock(lock_);
            sweep_locked(now);
        }

        /// Removes every entry (router stop).
        void clear()
        {
            std::scoped_lock lock(lock_);
            entries_.clear();
        }

        [[nodiscard]] std::size_t size() const
        {
            std::scoped_lock lock(lock_);
            return entries_.size();
        }

    private:
        struct entry
        {
            clock::time_point created_at;
            Endpoint original;
        };

        static constexpr uint32_t make_key(const uint16_t client_port, const uint16_t message_id) noexcept
        {
            return (static_cast<uint32_t>(client_port) << 16) | message_id;
        }

        void sweep_locked(const clock::time_point now)
        {
            for (auto it = entries_.begin(); it != entries_.end();)
            {
                if (now - it->second.created_at > ttl_)
                    it = entries_.erase(it);
                else
                    ++it;
            }
        }

        mutable std::mutex lock_;
        std::unordered_map<uint32_t, entry> entries_;
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

    /// How a datagram leaving a local UDP proxy listener is presented to the client.
    enum class dns_reply_restore : uint8_t
    {
        unchanged, ///< not a DNS override answer: present the relay's SOCKS5 header source
        restore,   ///< DNS override answer: present it as coming from the original server
        drop       ///< DNS override answer to no known query: drop it
    };

    /**
     * @brief Classifies a datagram relayed back by the DNS proxy while a server override is
     *        configured, and finds the server the resolver originally queried.
     *
     * Only an answer whose SOCKS5 header names the override server (address and port) is
     * treated as a DNS override answer; anything else relayed through the same proxy is left
     * unchanged. An override answer is restored to the original server recorded for
     * (@p client_port, DNS message ID), or dropped when there is no such query: delivering it
     * from the override address would only be rejected by the resolver.
     *
     * @param socks_datagram The UDP payload as relayed: SOCKS5 UDP header followed by the DNS message.
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
        if (!view || view->address_type != expected_address_type || view->address_size != override_address_size ||
            view->port != override_port ||
            !std::equal(view->address, view->address + view->address_size, override_address))
            return { dns_reply_restore::unchanged, std::nullopt };

        const auto message_id = dns_message_id(view->data, view->data_size);
        if (!message_id)
            return { dns_reply_restore::drop, std::nullopt };

        if (auto original = origins.resolve(client_port, *message_id))
            return { dns_reply_restore::restore, std::move(original) };

        return { dns_reply_restore::drop, std::nullopt };
    }

    // Compile-time checks of the decision table's key invariants.
    static_assert(decide_listener_reply(true, false) == listener_reply_action::drop,
        "An untranslatable listener reply must never be passed to the wire.");
    static_assert(decide_dns_route(dns_routing_mode::direct, 443, false, {}).action == dns_route_action::not_dns,
        "Non-DNS traffic must keep its ordinary routing.");
    static_assert(decide_dns_route(dns_routing_mode::direct, dns_port, false, {}).action == dns_route_action::pass,
        "Direct mode must pass DNS without consulting a proxy.");
    static_assert(decide_dns_route(dns_routing_mode::proxy, dns_port, false, {}).action == dns_route_action::block,
        "Proxy mode without a usable proxy must fail closed.");
    static_assert(decide_dns_route(dns_routing_mode::proxy, dns_port, true, {}).action == dns_route_action::pass,
        "ProxiFyre's own upstream traffic must never be captured recursively.");
}
