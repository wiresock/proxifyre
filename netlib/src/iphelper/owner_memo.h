#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <unordered_map>
#include <utility>

#include "owner_module_resolver.h"

namespace iphelper
{
    /// A row may have a usable fallback owner without having resolved its requested identity.
    template <class Process>
    struct owner_enrichment
    {
        std::shared_ptr<Process> owner;
        bool memoizable;

        owner_enrichment(std::shared_ptr<Process> value = {}, const bool complete = true) noexcept
            : owner(std::move(value)), memoizable(complete) {}
    };

    /**
     * @brief Owners already enriched during one captured connection table, keyed by (PID, service tag).
     *
     * A table holds many rows per process: every connection of a browser, a download manager or a
     * service. Enriching a row (process identity check, owner metadata, device path, the
     * network_process itself) gives the same result for every row of the same PID and service tag in
     * one enumeration, so it is done for the first such row and the object is shared by the rest.
     *
     * - Lifetime: one captured OS table. Nothing carries over to the next enumeration, so a PID that
     *   another process reuses later is enriched afresh. An IPv4 build that also folds rows from an
     *   AF_INET6 capture uses a separate memo for that capture: a PID may be reused between the two.
     * - Only complete successes are memoized. Failed enrichment is retried on the next row;
     *   a usable partial result (for example a service's host-image fallback) is returned for
     *   its row without suppressing the next row's attempt to resolve the requested identity.
     * - The service tag is part of the key: one svchost process can host several services, and a
     *   tagged row resolves to its service rather than to the host image.
     * - The process creation time is not: the table does not carry it, and learning it needs the
     *   very OpenProcess call this avoids. Within one build the first row's validation is the one
     *   closest to the enumeration, so a PID reused mid-build cannot make later rows of the same
     *   PID resolve to the new process (which re-validating every row could).
     * - The shared owner carries mutable per-owner routing state (exclusion and bypass flags,
     *   optional proxy ports). Those are decided from the owner's identity and the proxy
     *   configuration, which are the same for every row sharing it; confining sharing to one
     *   capture keeps that state from reaching another capture, protocol, family, or lookup.
     *
     * @tparam Process   Owner type (network_process), shared between the rows of one capture.
     * @tparam Allocator Allocator of the memo's storage. The memo is built inside the table build's
     *                   exception boundary, so an allocation failure fails that build.
     */
    template <class Process,
        class Allocator = std::allocator<std::pair<const std::uint64_t, std::shared_ptr<Process>>>>
    class owner_memo
    {
    public:
        /**
         * @brief Owner for a row of @p pid / @p service_tag.
         *
         * @param enrich Returns owner_enrichment<Process> (or a successful shared_ptr).
         * @return The memoized owner, else the enriched owner, including a non-memoizable fallback.
         * @throws std::bad_alloc if memoizing fails; nothing is memoized then.
         */
        template <class Enrich>
        std::shared_ptr<Process> resolve(const std::uint32_t pid, const std::uint32_t service_tag, Enrich&& enrich)
        {
            const auto key = (static_cast<std::uint64_t>(pid) << 32) | service_tag;
            if (const auto it = owners_.find(key); it != owners_.end())
                return it->second;

            const owner_enrichment<Process> result = enrich();
            if (result.owner && result.memoizable)
                owners_.emplace(key, result.owner);
            return result.owner;
        }

        /// Identities memoized so far.
        [[nodiscard]] std::size_t size() const noexcept { return owners_.size(); }

    private:
        std::unordered_map<std::uint64_t, std::shared_ptr<Process>,
            std::hash<std::uint64_t>, std::equal_to<std::uint64_t>, Allocator> owners_;
    };

    /**
     * @brief Owner of one owner-module table row (MIB_TCPROW_OWNER_MODULE and its TCPv6 / UDP kin),
     *        enriched at most once per (PID, service tag) in the capture that owns @p owners.
     *
     * Rows of PID 0 (TIME_WAIT and closed connections) and PID 4 go straight to @p enrich, which
     * skips them, so the memo stays out of the largest and cheapest part of the table.
     *
     * @param enrich owner_enrichment<Process>(Row*): the row's own enrichment.
     */
    template <class Process, class Allocator, class Row, class Enrich>
    std::shared_ptr<Process> memoized_owner(owner_memo<Process, Allocator>& owners, Row* row, Enrich&& enrich)
    {
        if (owner_module_resolver::is_system_process(row->dwOwningPid))
        {
            const owner_enrichment<Process> result = enrich(row);
            return result.owner;
        }

        return owners.resolve(row->dwOwningPid,
            owner_module_resolver::service_tag_from_owning_module_info(row->OwningModuleInfo),
            [&] { return enrich(row); });
    }
}
