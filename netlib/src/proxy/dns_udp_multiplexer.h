#pragma once

// Bookkeeping for the DNS proxy's shared SOCKS5 UDP association (socks5_dns_udp_relay.h).
//
// All UDP DNS queries of one address family travel through a single SOCKS5 UDP ASSOCIATE
// relay. Answers then no longer arrive per client socket, so each query's DNS message ID is
// replaced by a unique, randomly chosen relay ID on the way out, and the answer carrying that
// ID is mapped back to the client socket, its original ID and the server it queried.
//
// Like dns_routing_policy.h, this header is free of Windows, driver and socket types so it can
// be unit tested on any platform. The relay supplies time, randomness and raw datagrams.

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <unordered_map>

#include "dns_routing_policy.h"

namespace proxy
{
    /// Writes a DNS message ID (network byte order) into the first two bytes of @p payload.
    constexpr void set_dns_message_id(uint8_t* payload, const uint16_t id) noexcept
    {
        payload[0] = static_cast<uint8_t>(id >> 8);
        payload[1] = static_cast<uint8_t>(id & 0xff);
    }

    /// SOCKS5 UDP header size for an IPv4 (ATYP 1) or IPv6 (ATYP 4) address.
    [[nodiscard]] constexpr std::size_t socks5_udp_header_size(const uint8_t address_type) noexcept
    {
        return address_type == 1 ? 4 + 4 + 2 : address_type == 4 ? 4 + 16 + 2 : 0;
    }

    /**
     * @brief Validates a query the local redirect delivered to the DNS relay's listener and
     *        returns the offset of its DNS message.
     *
     * The redirect prepends a SOCKS5 UDP header of the listener's family (@p address_type)
     * naming the server to ask (the queried server or the server override). A datagram without
     * that header, or too short to carry a DNS header after it, cannot be multiplexed and is
     * dropped by the relay.
     */
    [[nodiscard]] constexpr std::optional<std::size_t> socks5_dns_query_offset(const uint8_t* datagram,
        const std::size_t size, const uint8_t address_type) noexcept
    {
        const auto view = parse_socks5_udp_datagram(datagram, size);
        if (!view || view->address_type != address_type || view->data_size < dns_header_size)
            return std::nullopt;
        return static_cast<std::size_t>(view->data - datagram);
    }

    /**
     * @brief Largest DNS answer the relay returns over UDP: the size that keeps the listener's
     *        reply (IP + UDP + SOCKS5 header + answer) within a 1280-byte packet, the IPv6
     *        minimum MTU, so it is never fragmented. A fragmented listener reply cannot be
     *        delivered: its first fragment is dropped.
     * @param address_type SOCKS5 ATYP of the listener's family: 1 (IPv4) or 4 (IPv6).
     */
    [[nodiscard]] constexpr std::size_t dns_udp_answer_limit(const uint8_t address_type) noexcept
    {
        constexpr std::size_t minimum_mtu = 1280;
        constexpr std::size_t udp_header = 8;
        const std::size_t ip_header = address_type == 1 ? 20 : 40;
        return minimum_mtu - ip_header - udp_header - socks5_udp_header_size(address_type);
    }

    /**
     * @brief Truncates a DNS answer larger than @p limit the way a server does when an answer
     *        does not fit (RFC 1035 section 4.2.1, RFC 7766): the TC bit is set, and only the
     *        header and question section are kept, so the resolver repeats the query over TCP.
     *
     * The answer, authority and additional counts are zeroed. If the question section cannot be
     * parsed, only the header is kept, with a zero question count.
     *
     * @return The new size (unchanged when @p size <= @p limit or the message has no header).
     */
    [[nodiscard]] constexpr std::size_t truncate_dns_answer(uint8_t* message, const std::size_t size,
        const std::size_t limit) noexcept
    {
        if (message == nullptr || size <= limit || size < dns_header_size)
            return size;

        const auto question_count = static_cast<std::size_t>((message[4] << 8) | message[5]);
        std::size_t end = dns_header_size;
        bool parsed = true;
        for (std::size_t question = 0; question < question_count && parsed; ++question)
        {
            // QNAME: labels ending with a zero byte, or a two-byte compression pointer.
            while (true)
            {
                if (end >= size)
                {
                    parsed = false;
                    break;
                }
                const auto length = message[end];
                if (length == 0)
                {
                    ++end;
                    break;
                }
                if ((length & 0xC0) == 0xC0)
                {
                    end += 2;
                    break;
                }
                if ((length & 0xC0) != 0)
                {
                    parsed = false;
                    break;
                }
                end += 1 + static_cast<std::size_t>(length);
            }
            end += 4; // QTYPE, QCLASS
            if (end > size || end > limit)
                parsed = false;
        }

        if (!parsed)
        {
            end = dns_header_size;
            message[4] = 0;
            message[5] = 0;
        }

        message[2] = static_cast<uint8_t>(message[2] | 0x02); // TC
        for (std::size_t field = 6; field < dns_header_size; ++field)
            message[field] = 0; // ANCOUNT, NSCOUNT, ARCOUNT
        return end;
    }

    /**
     * @brief Builds the datagram the DNS relay returns to a local client from an answer the
     *        SOCKS5 relay delivered.
     *
     * The output is a SOCKS5 UDP header of the listener's family naming the server the client
     * queried (@p server_address, @p server_port), followed by the DNS answer with the client's
     * original message ID. The local redirect presents the answer with that header's address as
     * its source, so the client sees an answer from the server it asked, whatever source and
     * address family the relay reported (always the override with a server override; for some
     * relays their own address).
     *
     * @param relayed The relay's datagram, already parsed (parse_socks5_udp_datagram()).
     * @param server_address Queried server address bytes (network byte order): 4 or 16 bytes.
     * @param original_id The client's DNS message ID.
     * An answer larger than dns_udp_answer_limit() is truncated (truncate_dns_answer()), so the
     * resolver retries over TCP instead of receiving a fragmented reply it would never get.
     *
     * @param out Output buffer.
     * @return Bytes written, or 0 when the answer does not fit, carries no DNS header, or
     *         @p address_size is not 4 or 16.
     */
    [[nodiscard]] inline std::size_t build_dns_client_answer(const socks5_udp_datagram_view& relayed,
        const uint8_t* server_address, const std::size_t address_size, const uint16_t server_port,
        const uint16_t original_id, uint8_t* out, const std::size_t out_capacity) noexcept
    {
        if (relayed.data == nullptr || relayed.data_size < dns_header_size || server_address == nullptr ||
            out == nullptr || (address_size != 4 && address_size != 16))
            return 0;

        const uint8_t address_type = address_size == 4 ? 1 : 4;
        const auto header_size = socks5_udp_header_size(address_type);
        if (out_capacity < header_size || out_capacity - header_size < relayed.data_size)
            return 0;

        out[0] = 0; // RSV
        out[1] = 0;
        out[2] = 0; // FRAG
        out[3] = address_type;
        std::memcpy(out + 4, server_address, address_size);
        out[4 + address_size] = static_cast<uint8_t>(server_port >> 8);
        out[4 + address_size + 1] = static_cast<uint8_t>(server_port & 0xff);
        std::memmove(out + header_size, relayed.data, relayed.data_size);
        set_dns_message_id(out + header_size, original_id);
        return header_size + truncate_dns_answer(out + header_size, relayed.data_size,
            dns_udp_answer_limit(address_type));
    }

    /**
     * @brief Queries in flight through the shared association, keyed by relay ID.
     *
     * insert() replaces a query's message ID with a relay ID that is unique among the queries in
     * flight and chosen by the caller's random source, so the 16-bit ID keeps its full entropy
     * against forged answers. A retransmission (same client socket and original ID) reuses its
     * relay ID, so duplicate answers map to it and it counts once as unanswered. Entries expire
     * after the TTL; the table is bounded, and when full the oldest query is evicted.
     *
     * Not thread-safe: the relay serializes access.
     *
     * @tparam Client Client socket identity (equality-comparable, hashed by @p Hash). The relay
     *         uses the listener's sender endpoint: the queried server address and the client port.
     */
    template <typename Client, typename Hash = std::hash<Client>, typename Clock = std::chrono::steady_clock>
    class dns_query_table
    {
    public:
        using time_point = typename Clock::time_point;

        struct pending
        {
            Client client;
            uint16_t original_id{};
        };

        dns_query_table(const std::chrono::seconds ttl, const std::size_t capacity)
            : ttl_(ttl), capacity_(std::max<std::size_t>(capacity, 1))
        {
        }

        /**
         * @brief Records a query and returns its relay ID.
         * @param random Callable returning a uniformly distributed uint16_t.
         * @return The relay ID, or std::nullopt only if no ID could be found (cannot happen while
         *         the capacity is below 65536).
         */
        template <typename Random>
        std::optional<uint16_t> insert(const Client& client, const uint16_t original_id, const time_point now,
            Random&& random)
        {
            const key k{ client, original_id };
            if (const auto existing = by_client_.find(k); existing != by_client_.end())
            {
                auto& entry = entries_.at(existing->second);
                entry.sent_at = now;
                return existing->second;
            }

            // Expiry is left to expire(), which reports the unanswered count; a full table only
            // evicts its oldest query.
            if (entries_.size() >= capacity_)
                evict_oldest();

            // Random probing; the table holds at most capacity_ of 65536 IDs, so a free ID is
            // found within a few draws. Fall back to a linear scan from a random start.
            std::optional<uint16_t> relay_id;
            for (int attempt = 0; attempt < 16 && !relay_id; ++attempt)
            {
                const auto candidate = static_cast<uint16_t>(random());
                if (!entries_.contains(candidate))
                    relay_id = candidate;
            }
            if (!relay_id)
            {
                const auto start = static_cast<uint16_t>(random());
                for (uint32_t step = 0; step < 0x10000 && !relay_id; ++step)
                {
                    const auto candidate = static_cast<uint16_t>(start + step);
                    if (!entries_.contains(candidate))
                        relay_id = candidate;
                }
            }
            if (!relay_id)
                return std::nullopt;

            entries_.emplace(*relay_id, entry{ client, original_id, now });
            by_client_.emplace(k, *relay_id);
            return relay_id;
        }

        /**
         * @brief Removes and returns the query an answer with @p relay_id belongs to.
         * @return std::nullopt for an unknown or expired relay ID.
         */
        std::optional<pending> take(const uint16_t relay_id, const time_point now)
        {
            const auto it = entries_.find(relay_id);
            if (it == entries_.end())
                return std::nullopt;

            const bool expired = now - it->second.sent_at > ttl_;
            pending result{ it->second.client, it->second.original_id };
            erase(it);
            if (expired)
                return std::nullopt;
            return result;
        }

        /// Removes queries older than the TTL and returns how many expired unanswered.
        std::size_t expire(const time_point now)
        {
            std::size_t expired = 0;
            for (auto it = entries_.begin(); it != entries_.end();)
            {
                if (now - it->second.sent_at > ttl_)
                {
                    it = erase(it);
                    ++expired;
                }
                else
                {
                    ++it;
                }
            }
            return expired;
        }

        void clear() noexcept
        {
            entries_.clear();
            by_client_.clear();
        }

        [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }
        [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }

    private:
        struct entry
        {
            Client client;
            uint16_t original_id{};
            time_point sent_at{};
        };

        struct key
        {
            Client client;
            uint16_t original_id{};
            bool operator==(const key& rhs) const { return client == rhs.client && original_id == rhs.original_id; }
        };

        struct key_hash
        {
            std::size_t operator()(const key& k) const noexcept
            {
                return Hash{}(k.client) ^ (static_cast<std::size_t>(k.original_id) * 0x9E3779B1u);
            }
        };

        using entries_t = std::unordered_map<uint16_t, entry>;

        typename entries_t::iterator erase(typename entries_t::iterator it)
        {
            by_client_.erase(key{ it->second.client, it->second.original_id });
            return entries_.erase(it);
        }

        void evict_oldest()
        {
            const auto oldest = std::min_element(entries_.begin(), entries_.end(),
                [](const auto& a, const auto& b) { return a.second.sent_at < b.second.sent_at; });
            if (oldest != entries_.end())
                erase(oldest);
        }

        entries_t entries_;
        std::unordered_map<key, uint16_t, key_hash> by_client_;
        std::chrono::seconds ttl_;
        std::size_t capacity_;
    };

    /**
     * @brief Decides when the shared association is reopened and when a new one may be tried.
     *
     * - A failed open is retried after a backoff that doubles from 1 s up to 30 s; queries
     *   arriving meanwhile are dropped (Proxy mode never sends DNS directly).
     * - An open association is reopened when its SOCKS5 control connection closes or the relay
     *   socket fails (reported by the relay), or when it looks silently dead: at least
     *   @p unanswered_limit queries in a row expired without any datagram arriving from the
     *   relay in between, and the association is at least @p minimum_age old. The age limit
     *   keeps a resolver that never answers from churning a working association.
     *
     * Not thread-safe: the relay serializes access.
     */
    template <typename Clock = std::chrono::steady_clock>
    class dns_association_health
    {
    public:
        using time_point = typename Clock::time_point;

        explicit dns_association_health(const std::size_t unanswered_limit = 3,
            const std::chrono::seconds minimum_age = std::chrono::seconds{ 30 })
            : unanswered_limit_(std::max<std::size_t>(unanswered_limit, 1)), minimum_age_(minimum_age)
        {
        }

        /// Whether opening an association may be attempted at @p now.
        [[nodiscard]] bool may_open(const time_point now) const noexcept
        {
            return failures_ == 0 || now >= next_attempt_;
        }

        void on_open_failed(const time_point now) noexcept
        {
            ++failures_;
            const auto shift = std::min<std::size_t>(failures_ - 1, 5); // 1, 2, 4, 8, 16, 32 s
            next_attempt_ = now + (std::min)(std::chrono::seconds{ 1 } * (1u << shift), max_backoff);
        }

        void on_opened(const time_point now) noexcept
        {
            failures_ = 0;
            unanswered_ = 0;
            opened_at_ = now;
        }

        /// Any datagram from the relay shows the association is alive.
        void on_relay_datagram() noexcept { unanswered_ = 0; }

        /// Records queries that expired unanswered; true when the association should be reopened.
        [[nodiscard]] bool on_unanswered(const std::size_t count, const time_point now) noexcept
        {
            unanswered_ += count;
            return unanswered_ >= unanswered_limit_ && now - opened_at_ >= minimum_age_;
        }

        [[nodiscard]] std::size_t consecutive_failures() const noexcept { return failures_; }
        [[nodiscard]] time_point next_attempt() const noexcept { return next_attempt_; }

        static constexpr std::chrono::seconds max_backoff{ 30 };

    private:
        std::size_t unanswered_limit_;
        std::chrono::seconds minimum_age_;
        std::size_t failures_{};
        std::size_t unanswered_{};
        time_point next_attempt_{};
        time_point opened_at_{};
    };
}
