#pragma once

#pragma warning( push )
#pragma warning( disable : 26490 ) // disable reinterpret_cast warning

namespace net
{
    /// <summary>
    /// IPv6 helper functions for parsing IPv6 headers, checksum and etc..
    /// </summary>
    struct ipv6_helper
    {
        // ********************************************************************************
        /// <summary>
        /// Parses IP headers until the transport payload
        /// </summary>
        /// <param name="ip_header">pointer to IP header</param>
        /// <param name="packet_size">size of IP packet in octets</param>
        /// <returns>pointer to IP packet payload (TCP, UDP, ICMPv6 and etc..) and protocol value</returns>
        // ********************************************************************************
        static std::pair<void*, unsigned char> find_transport_header(
            const ipv6hdr* ip_header,
            const unsigned packet_size
        ) noexcept
        {
            unsigned char next_proto = 0;

            //
            // Parse IPv6 headers
            //

            // Check if this IPv6 packet
            if (ip_header->ip6_v != 6)
            {
                return {nullptr, next_proto};
            }

            // Find the first header
            next_proto = ip_header->ip6_next;
            auto* next_header = reinterpret_cast<const ipv6ext*>(ip_header + 1);

            // Loop until we find the last IP header
            while (true)
            {
                // Ensure that current header is still within the packet
                if (reinterpret_cast<const char*>(next_header) > reinterpret_cast<const char*>(ip_header) + packet_size
                    - sizeof(
                        ipv6ext))
                {
                    return {nullptr, next_proto};
                }

                switch (next_proto)
                {
                // Fragmentation
                case IPPROTO_FRAGMENT:
                    {
                        const auto frag = reinterpret_cast<const ipv6ext_frag*>(next_header);

                        // If this isn't the FIRST fragment, there won't be a TCP/UDP header anyway
                        if ((frag->ip6_offlg & 0xFC) != 0)
                        {
                            // The offset is non-zero
                            next_proto = frag->ip6_next;

                            return {nullptr, next_proto};
                        }

                        // Otherwise it's either an entire segment or the first fragment
                        next_proto = frag->ip6_next;

                        // Return next octet following the fragmentation header
                        next_header = reinterpret_cast<const ipv6ext*>(reinterpret_cast<const char*>(next_header) +
                            sizeof(
                                ipv6ext_frag));

                        return {const_cast<void*>(static_cast<const void*>(next_header)), next_proto};
                    }

                // Headers we just skip over
                case IPPROTO_HOPOPTS:
                case IPPROTO_ROUTING:
                case IPPROTO_DSTOPTS:
                    next_proto = next_header->ip6_next;

                // As per RFC 2460 : ip6ext_len specifies the extended
                // header length, in units of 8 octets *not including* the
                // first 8 octets.

                    next_header = reinterpret_cast<const ipv6ext*>(reinterpret_cast<const char*>(next_header) + 8 +
                        static_cast<ULONG_PTR>(next_header
                            ->ip6_len) * 8);
                    break;

                default:
                    // No more IPv6 headers to skip
                    return {const_cast<void*>(static_cast<const void*>(next_header)), next_proto};
                }
            }
        }

        // ********************************************************************************
        /// <summary>
        /// Recalculates TCP/UDP checksum for IPv6 packet in INTERMEDIATE_BUFFER container 
        /// </summary>
        /// <param name="packet">pinter to INTERMEDIATE_BUFFER structure</param>
        // ********************************************************************************
        static void recalculate_tcp_udp_checksum(PINTERMEDIATE_BUFFER packet)
        {
            tcphdr_ptr tcp_header = nullptr;
            udphdr_ptr udp_header = nullptr;
            icmpv6hdr_ptr icmp_header = nullptr;

            const auto ipv6_header = reinterpret_cast<ipv6hdr_ptr>(&packet->m_IBuffer[ETHER_HEADER_LENGTH]);
            auto [header, protocol] = find_transport_header(ipv6_header, packet->m_Length - ETHER_HEADER_LENGTH);

            if (header == nullptr)
                return;

            if (protocol == IPPROTO_TCP)
            {
                tcp_header = static_cast<tcphdr_ptr>(header);
                tcp_header->th_sum = 0;
            }
            else if (protocol == IPPROTO_UDP)
            {
                udp_header = static_cast<udphdr_ptr>(header);
                udp_header->th_sum = 0;
            }
            else if (protocol == IPPROTO_ICMPV6)
            {
                icmp_header = static_cast<icmpv6hdr_ptr>(header);
                icmp_header->checksum = 0;
            }

            if (const auto checksum = tcp_udp_v6_checksum(
                    &ipv6_header->ip6_src,
                    &ipv6_header->ip6_dst,
                    protocol,
                    header,
                    packet->m_Length - static_cast<uint32_t>(static_cast<uint8_t*>(header) - packet->m_IBuffer));
                protocol
                == IPPROTO_TCP)
            {
                tcp_header->th_sum = checksum;
            }
            else if (protocol == IPPROTO_UDP)
            {
                udp_header->th_sum = checksum;
            }
            else if (protocol == IPPROTO_ICMPV6)
            {
                icmp_header->checksum = checksum;
            }
        }

    private:
        /// <summary>
        /// Calculates partial IP checksum
        /// </summary>
        /// <param name="p">buffer pointer to calculate the checksum</param>
        /// <param name="len">length of data buffer</param>
        /// <param name="sum">pre-calculated checksum</param>
        /// <returns></returns>
        static uint64_t ip_checksum_partial(const void* p, size_t len, uint64_t sum)
        {
            /*Main loop: 32 bits at a time.
            We take advantage of intel's ability to do unaligned memory
            accesses with minimal additional cost. Other architectures
            probably want to be more careful here.*/

            auto p32 = static_cast<const uint32_t*>(p);
            for (; len >= sizeof(*p32); len -= sizeof(*p32))
                sum += *p32++;

            /*Handle un-32bit-aligned trailing bytes*/
            auto p16 = reinterpret_cast<const uint16_t*>(p32);
            if (len >= 2)
            {
                sum += *p16++;
                len -= sizeof(*p16);
            }
            if (len > 0)
            {
                const auto p8 = reinterpret_cast<const uint8_t*>(p16);
                sum += ntohs(*p8 << 8); /* RFC says pad last byte */
            }

            return sum;
        }

        /// <summary>
        /// Fold 64 bit checksum into 16 bit value
        /// </summary>
        /// <param name="sum"></param>
        /// <returns></returns>
        static uint16_t ip_checksum_fold(uint64_t sum)
        {
            while (sum & ~0xffffffffULL)
                sum = (sum >> 32) + (sum & 0xffffffffULL);
            while (sum & 0xffff0000ULL)
                sum = (sum >> 16) + (sum & 0xffffULL);

            return static_cast<uint16_t>(~sum);
        }

        /// <summary>
        /// Calculates partial (pseudo-header) TCP/UDP checksum
        /// </summary>
        /// <param name="src_ip">source IP address</param>
        /// <param name="dst_ip">destination IP address</param>
        /// <param name="protocol">IP protocol</param>
        /// <param name="len">length of the TCP/UDP packet including header</param>
        /// <returns>64 bit checksum value</returns>
        static uint64_t tcp_udp_v6_header_checksum_partial(const in6_addr* src_ip, const in6_addr* dst_ip,
                                                           const uint8_t protocol, const uint32_t len)
        {
            /* The IPv6 pseudo-header is defined in RFC 2460, Section 8.1. */
            struct ipv6_pseudo_header_t
            {
                union
                {
                    struct header
                    {
                        in6_addr src_ip;
                        in6_addr dst_ip;
                        uint32_t length;
                        uint8_t mbz[3];
                        uint8_t next_header;
                    } fields;

                    uint32_t words[10];
                };
            };

            ipv6_pseudo_header_t pseudo_header{};
            assert(sizeof(pseudo_header) == 40);

            /* Fill in the pseudo-header. */
            pseudo_header.fields.src_ip = *src_ip;
            pseudo_header.fields.dst_ip = *dst_ip;
            pseudo_header.fields.length = htonl(len);
            memset(pseudo_header.fields.mbz, 0, sizeof(pseudo_header.fields.mbz));
            pseudo_header.fields.next_header = protocol;
            return ip_checksum_partial(&pseudo_header, sizeof(pseudo_header), 0);
        }

        // ********************************************************************************
        /// <summary>
        /// Calculates TCP/UDP checksum for IPv6 packet. Current checksum in the packet 
        /// must be zeroed.
        /// </summary>
        /// <param name="src_ip">source IPv6 address</param>
        /// <param name="dst_ip">destination IPv6 address</param>
        /// <param name="protocol">network protocol</param>
        /// <param name="payload">pointer to transport header</param>
        /// <param name="len">length of the TCP/UDP packet including header</param>
        /// <returns>calculated checksum in network order</returns>
        // ********************************************************************************
        static uint16_t tcp_udp_v6_checksum(const struct in6_addr* src_ip, const struct in6_addr* dst_ip,
                                            const uint8_t protocol, const void* payload, const uint32_t len)
        {
            auto sum = tcp_udp_v6_header_checksum_partial(src_ip, dst_ip, protocol, len);
            sum = ip_checksum_partial(payload, len, sum);
            return ip_checksum_fold(sum);
        }
    };
}

#pragma warning( pop )
