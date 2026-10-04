#pragma once

// Allocation-failure injection for the production default-allocator path.
//
// allocation_fault.cpp replaces the global operator new / operator delete of this test executable
// with a pass-through to malloc / free that the calling thread can arm: while armed, the thread's
// allocations are counted and the chosen one throws std::bad_alloc, exactly as an exhausted heap
// would through std::allocator. Nothing else changes while it is not armed. Only probes that run
// in a subprocess arm it (see the DISABLED_*Probe tests), because a failure inside a noexcept
// function terminates the process.

namespace netlib_test::allocation_fault
{
    /// Starts counting the calling thread's allocations; the @p fail_at-th one (1-based) throws
    /// std::bad_alloc and disarms. 0 counts only.
    void arm(int fail_at) noexcept;

    void disarm() noexcept;

    /// Allocations of the armed thread counted since arm().
    int count() noexcept;

    /// Whether the chosen allocation has failed since arm().
    bool triggered() noexcept;
}
