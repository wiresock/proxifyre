#pragma once

#pragma warning( push )
#pragma warning( disable : 26456 )

namespace netlib::winsys
{
    // --------------------------------------------------------------------------------
    /// <summary>
    /// RAII wrapper for Windows event objects.
    /// Provides convenient methods for event signaling, resetting, and waiting.
    /// 
    /// IMPORTANT NOTES:
    /// - Methods assume the wrapped handle is valid. Check valid() after construction
    ///   or use the static factory methods for safer initialization.
    /// - For auto-reset events, is_signaled() is DESTRUCTIVE: it consumes the signal
    ///   if the event is signaled (because it uses WaitForSingleObject internally).
    /// - Error handling: Methods return false/WAIT_FAILED on error; use GetLastError()
    ///   for detailed error information.
    /// </summary>
    // --------------------------------------------------------------------------------
    class safe_event final : public safe_object_handle
    {
        using base_type = safe_object_handle;

    public:
        /// <summary>
        /// Constructs safe_event from an event object handle.
        /// </summary>
        /// <param name="handle">Event handle (typically from CreateEvent)</param>
        explicit safe_event(HANDLE handle = nullptr) noexcept
            : base_type(handle)
        {
        }

        /// <summary>
        /// Deleted copy constructor (events cannot be copied)
        /// </summary>
        safe_event(const safe_event&) = delete;

        /// <summary>
        /// Move constructor
        /// </summary>
        safe_event(safe_event&&) noexcept = default;

        /// <summary>
        /// Deleted copy assignment (events cannot be copied)
        /// </summary>
        safe_event& operator=(const safe_event&) = delete;

        /// <summary>
        /// Move assignment
        /// </summary>
        safe_event& operator=(safe_event&&) noexcept = default;

        /// <summary>
        /// Default destructor (automatically closes event handle)
        /// </summary>
        ~safe_event() = default;

        // ============================================================================
        // Factory Methods
        // ============================================================================

        /// <summary>
        /// Creates a manual-reset event object.
        /// Manual-reset events remain signaled until explicitly reset.
        /// </summary>
        /// <param name="initially_signaled">Whether the event starts in signaled state</param>
        /// <param name="name">Optional event name for inter-process synchronization</param>
        /// <returns>safe_event object (check valid() or operator bool() for success)</returns>
        /// <remarks>
        /// If the named event already exists, CreateEventW succeeds and returns a handle to it.
        /// Use GetLastError() == ERROR_ALREADY_EXISTS to detect this condition if needed.
        /// </remarks>
        [[nodiscard]] static safe_event create_manual_reset(
            const bool initially_signaled = false,
            const wchar_t* name = nullptr) noexcept
        {
            return safe_event(CreateEventW(nullptr, TRUE, initially_signaled, name));
        }

        /// <summary>
        /// Creates an auto-reset event object.
        /// Auto-reset events automatically reset to non-signaled after a successful wait.
        /// </summary>
        /// <param name="initially_signaled">Whether the event starts in signaled state</param>
        /// <param name="name">Optional event name for inter-process synchronization</param>
        /// <returns>safe_event object (check valid() or operator bool() for success)</returns>
        /// <remarks>
        /// If the named event already exists, CreateEventW succeeds and returns a handle to it.
        /// Use GetLastError() == ERROR_ALREADY_EXISTS to detect this condition if needed.
        /// </remarks>
        [[nodiscard]] static safe_event create_auto_reset(
            const bool initially_signaled = false,
            const wchar_t* name = nullptr) noexcept
        {
            return safe_event(CreateEventW(nullptr, FALSE, initially_signaled, name));
        }

        // ============================================================================
        // Event Operations
        // ============================================================================

        /// <summary>
        /// Waits for the event to become signaled.
        /// </summary>
        /// <param name="milliseconds">Timeout in milliseconds (INFINITE for no timeout)</param>
        /// <returns>WAIT_OBJECT_0 if signaled, WAIT_TIMEOUT if timeout, WAIT_FAILED on error</returns>
        [[nodiscard]] DWORD wait(const DWORD milliseconds = INFINITE) const noexcept
        {
            if (!valid()) {
                return WAIT_FAILED;
            }
            return WaitForSingleObject(get(), milliseconds);
        }

        /// <summary>
        /// Waits for the event to become signaled (chrono overload).
        /// Non-positive durations are treated as immediate poll (0 timeout).
        /// Durations exceeding DWORD_MAX milliseconds are treated as infinite wait.
        /// </summary>
        /// <param name="timeout">Timeout duration</param>
        /// <returns>WAIT_OBJECT_0 if signaled, WAIT_TIMEOUT if timeout, WAIT_FAILED on error</returns>
        [[nodiscard]] DWORD wait(const std::chrono::milliseconds timeout) const noexcept
        {
            if (!valid())
            {
                return WAIT_FAILED;
            }

            const auto count = timeout.count();

            // Non-positive timeout becomes immediate poll
            if (count <= 0)
            {
                return WaitForSingleObject(get(), 0);
            }

            // At this point, count is guaranteed positive (> 0), so safe to compare with DWORD max.
            // If count exceeds what DWORD can represent, use infinite wait.
            // Note: INFINITE == DWORD_MAX (0xFFFFFFFF), so values >= INFINITE become infinite wait.
            constexpr auto max_timeout = static_cast<std::chrono::milliseconds::rep>(
                std::numeric_limits<DWORD>::max());

            if (count >= max_timeout)
            {
                return WaitForSingleObject(get(), INFINITE);
            }

            // Normal case: count is in range (0, DWORD_MAX), safe to cast
            return WaitForSingleObject(get(), static_cast<DWORD>(count));
        }

        /// <summary>
        /// Waits for the event and returns true if it was signaled (not timeout/error).
        /// </summary>
        /// <param name="milliseconds">Timeout in milliseconds (INFINITE for no timeout)</param>
        /// <returns>true if event was signaled, false on timeout or error</returns>
        /// <remarks>
        /// This is a convenience method. If you need to distinguish timeout from error,
        /// use the raw wait() method and check GetLastError() when it returns WAIT_FAILED.
        /// </remarks>
        [[nodiscard]] bool wait_signaled(const DWORD milliseconds = INFINITE) const noexcept
        {
            return wait(milliseconds) == WAIT_OBJECT_0;
        }

        /// <summary>
        /// Checks if the event is currently signaled (non-blocking).
        /// 
        /// WARNING: For AUTO-RESET events, this method is DESTRUCTIVE!
        /// If the event is signaled, this call will CONSUME the signal and reset the event
        /// (because it internally uses WaitForSingleObject with 0 timeout).
        /// 
        /// For MANUAL-RESET events, this is a safe non-blocking query.
        /// </summary>
        /// <returns>true if signaled, false otherwise</returns>
        [[nodiscard]] bool is_signaled() const noexcept
        {
            return wait(0) == WAIT_OBJECT_0;
        }

        /// <summary>
        /// Sets the event to signaled state.
        /// For manual-reset events, the event remains signaled until reset_event() is called.
        /// For auto-reset events, the event resets automatically after one waiting thread is released.
        /// </summary>
        /// <returns>true if successful, false on error (check GetLastError() for details)</returns>
        [[nodiscard]] bool signal() const noexcept
        {
            assert(valid() && "Attempting to signal invalid event handle");
            return SetEvent(get()) != FALSE;
        }

        /// <summary>
        /// Resets the event to non-signaled state.
        /// Only meaningful for manual-reset events; auto-reset events reset automatically.
        /// 
        /// Note: Named reset_event() to avoid confusion with std::unique_ptr::reset()
        /// which would change the owned handle itself rather than the event's signaled state.
        /// </summary>
        /// <returns>true if successful, false on error (check GetLastError() for details)</returns>
        [[nodiscard]] bool reset_event() const noexcept
        {
            assert(valid() && "Attempting to reset invalid event handle");
            return ResetEvent(get()) != FALSE;
        }
    };
}
#pragma warning( pop )