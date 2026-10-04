#include "pch.h"
#include "allocation_fault.h"

#include <cstdlib>
#include <new>

namespace
{
    std::atomic<DWORD> armed_thread{ 0 };   // 0: not armed
    std::atomic<int> counter{ 0 };
    std::atomic<int> fail_at{ 0 };
    std::atomic<bool> triggered_{ false };

    void* allocate(const std::size_t size)
    {
        if (armed_thread.load(std::memory_order_relaxed) == ::GetCurrentThreadId())
        {
            const int n = counter.fetch_add(1, std::memory_order_relaxed) + 1;
            if (n == fail_at.load(std::memory_order_relaxed))
            {
                armed_thread.store(0, std::memory_order_relaxed);
                triggered_.store(true, std::memory_order_relaxed);
                throw std::bad_alloc();
            }
        }

        if (void* const p = std::malloc(size == 0 ? 1 : size))
            return p;
        throw std::bad_alloc();
    }

    void* allocate_nothrow(const std::size_t size) noexcept
    {
        try
        {
            return allocate(size);
        }
        catch (...)
        {
            return nullptr;
        }
    }
}

namespace netlib_test::allocation_fault
{
    void arm(const int fail) noexcept
    {
        counter.store(0, std::memory_order_relaxed);
        triggered_.store(false, std::memory_order_relaxed);
        fail_at.store(fail, std::memory_order_relaxed);
        armed_thread.store(::GetCurrentThreadId(), std::memory_order_relaxed);
    }

    void disarm() noexcept { armed_thread.store(0, std::memory_order_relaxed); }

    int count() noexcept { return counter.load(std::memory_order_relaxed); }

    bool triggered() noexcept { return triggered_.load(std::memory_order_relaxed); }
}

// The replaceable global allocation functions ([new.delete.single], [new.delete.array]).
// Alignment-aware forms are not replaced: nothing under test uses over-aligned types.

void* operator new(const std::size_t size) { return allocate(size); }
void* operator new[](const std::size_t size) { return allocate(size); }
void* operator new(const std::size_t size, const std::nothrow_t&) noexcept { return allocate_nothrow(size); }
void* operator new[](const std::size_t size, const std::nothrow_t&) noexcept { return allocate_nothrow(size); }

void operator delete(void* const p) noexcept { std::free(p); }
void operator delete[](void* const p) noexcept { std::free(p); }
void operator delete(void* const p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* const p, std::size_t) noexcept { std::free(p); }
void operator delete(void* const p, const std::nothrow_t&) noexcept { std::free(p); }
void operator delete[](void* const p, const std::nothrow_t&) noexcept { std::free(p); }
