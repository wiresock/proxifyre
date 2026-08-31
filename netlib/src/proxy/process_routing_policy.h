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
}
