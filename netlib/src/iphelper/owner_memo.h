#pragma once

#include <bit>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
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
     * @brief Identities already enriched during one captured connection table, keyed by (PID, service tag).
     *
     * A table holds many rows per process: every connection of a browser, a download manager or a
     * service. Enriching a row (process identity check, owner metadata, device path) gives the same
     * result for every row of the same PID and service tag in one enumeration, so it is done for
     * the first such row and the resulting identity is shared by the rest.
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
     * - What is shared is immutable: the enriched identity (iphelper::owner_identity). The
     *   routing state the packet handlers cache (exclusion and transport bypass flags, optional
     *   proxy ports) lives on each row's own owner object (iphelper::network_process), which the
     *   table build creates from the shared identity. A decision cached while routing one
     *   connection therefore never applies to another connection of the same process, so a
     *   runtime change to the proxy configuration (a new association or exclusion) takes effect
     *   for every connection not yet routed, as it did before enrichment was memoized.
     *
     * Storage: one array of slots forming an open-addressing hash table (linear probing,
     * power-of-two capacity, load factor at most 1/2), allocated through @p Allocator.
     * Construction allocates nothing, and the only allocations are the array growths in grow(),
     * an ordinary throwing function: an allocation failure therefore always unwinds to the
     * table build's catch, and never happens inside a noexcept function. (The node-based
     * std::unordered_map used before allocated its iterator-debugging proxy inside a noexcept
     * constructor of the MSVC Debug STL, where a failure terminates the process.) A capture
     * with N identities makes about log2(N / 8) + 1 allocations of 16, 32, 64, ... slots of
     * 24 bytes, against 2 + N node allocations plus bucket rehashes before; a lookup is one
     * multiply-shift hash and a short probe through contiguous memory.
     *
     * @tparam Process   Memoized type (const owner_identity), shared between the rows of one capture.
     * @tparam Allocator Allocator of the memo's storage, rebound to the slot type. The memo is
     *                   built inside the table build's exception boundary, so an allocation
     *                   failure fails that build; a failed growth memoizes nothing and leaves the
     *                   identities already memoized in place.
     */
    template <class Process,
        class Allocator = std::allocator<std::pair<const std::uint64_t, std::shared_ptr<Process>>>>
    class owner_memo
    {
    public:
        using owner_ptr = std::shared_ptr<Process>;

        /// Slots of the first allocation; each growth doubles the capacity.
        static constexpr std::size_t initial_capacity = 16;

        owner_memo() noexcept = default;
        owner_memo(const owner_memo&) = delete;
        owner_memo& operator=(const owner_memo&) = delete;
        ~owner_memo() { release(); }

        /**
         * @brief Owner for a row of @p pid / @p service_tag.
         *
         * @param enrich Returns owner_enrichment<Process> (or a successful shared_ptr).
         * @return The memoized owner, else the enriched owner, including a non-memoizable fallback.
         * @throws std::bad_alloc if memoizing fails; nothing is memoized then.
         */
        template <class Enrich>
        owner_ptr resolve(const std::uint32_t pid, const std::uint32_t service_tag, Enrich&& enrich)
        {
            const auto key = (static_cast<std::uint64_t>(pid) << 32) | service_tag;
            if (const auto* const found = find(key))
                return found->owner;

            const owner_enrichment<Process> result = enrich();
            if (result.owner && result.memoizable)
                insert(key, result.owner);
            return result.owner;
        }

        /// Identities memoized so far.
        [[nodiscard]] std::size_t size() const noexcept { return size_; }

        /// Slots currently allocated: 0 until the first identity is memoized.
        [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }

    private:
        struct slot
        {
            std::uint64_t key{};
            owner_ptr owner;    // null: the slot is empty
        };

        using slot_allocator = typename std::allocator_traits<Allocator>::template rebind_alloc<slot>;
        using slot_traits = std::allocator_traits<slot_allocator>;

        /// Fibonacci hashing: the high bits of the product spread sequential PIDs (multiples of
        /// four) and small service tags over the table. @p shift is 64 - log2(capacity).
        [[nodiscard]] static std::size_t index_of(const std::uint64_t key, const unsigned shift) noexcept
        {
            return static_cast<std::size_t>((key * 0x9E3779B97F4A7C15ull) >> shift);
        }

        [[nodiscard]] const slot* find(const std::uint64_t key) const noexcept
        {
            if (capacity_ == 0)
                return nullptr;

            const std::size_t mask = capacity_ - 1;
            for (std::size_t i = index_of(key, shift_);; i = (i + 1) & mask)
            {
                if (!slots_[i].owner)
                    return nullptr;
                if (slots_[i].key == key)
                    return &slots_[i];
            }
        }

        /// Stores @p owner in the first empty slot of its probe sequence (the table always has
        /// room: insert() grows it before the load factor would exceed 1/2).
        static void place(slot* const slots, const std::size_t capacity, const unsigned shift,
            const std::uint64_t key, owner_ptr owner) noexcept
        {
            const std::size_t mask = capacity - 1;
            std::size_t i = index_of(key, shift);
            while (slots[i].owner)
                i = (i + 1) & mask;
            slots[i].key = key;
            slots[i].owner = std::move(owner);
        }

        /// @throws std::bad_alloc from grow(), before anything has changed.
        void insert(const std::uint64_t key, owner_ptr owner)
        {
            if ((size_ + 1) * 2 > capacity_)
                grow();
            place(slots_, capacity_, shift_, key, std::move(owner));
            ++size_;
        }

        /// Doubles the storage (initial_capacity first). The new array is allocated before the
        /// memo is touched, so a failed allocation leaves it exactly as it was.
        void grow()
        {
            const std::size_t capacity = capacity_ == 0 ? initial_capacity : capacity_ * 2;
            const auto shift = static_cast<unsigned>(64 - std::countr_zero(capacity));
            slot* const slots = slot_traits::allocate(alloc_, capacity);     // may throw
            for (std::size_t i = 0; i < capacity; ++i)
                slot_traits::construct(alloc_, slots + i);                  // noexcept: an empty slot
            for (std::size_t i = 0; i < capacity_; ++i)
                if (slots_[i].owner)
                    place(slots, capacity, shift, slots_[i].key, std::move(slots_[i].owner));
            release();
            slots_ = slots;
            capacity_ = capacity;
            shift_ = shift;
        }

        void release() noexcept
        {
            if (slots_ == nullptr)
                return;
            for (std::size_t i = 0; i < capacity_; ++i)
                slot_traits::destroy(alloc_, slots_ + i);
            slot_traits::deallocate(alloc_, slots_, capacity_);
            slots_ = nullptr;
            capacity_ = 0;
        }

        slot_allocator alloc_{};
        slot* slots_{ nullptr };
        std::size_t capacity_{ 0 };
        std::size_t size_{ 0 };
        unsigned shift_{ 64 };  // unused while capacity_ == 0
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
