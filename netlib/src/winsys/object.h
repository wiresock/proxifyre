#pragma once

#pragma warning( push )
#pragma warning( disable : 26456 )

namespace netlib::winsys
{
    // --------------------------------------------------------------------------------
    /// <summary>
    /// Stateless deleter for Windows kernel object handles.
    /// </summary>
    // --------------------------------------------------------------------------------
    struct handle_deleter
    {
        using pointer = HANDLE;

        void operator()(HANDLE handle) const noexcept
        {
            // Note: Both nullptr and INVALID_HANDLE_VALUE are considered invalid
            if (handle && (handle != INVALID_HANDLE_VALUE))
                CloseHandle(handle);
        }
    };

    // --------------------------------------------------------------------------------
    /// <summary>
    /// RAII wrapper for Windows kernel object handles that must be closed with CloseHandle.
    /// 
    /// Suitable for: Events, Mutexes, Semaphores, Files, Process/Thread handles, etc.
    /// 
    /// WARNING: Do NOT use with pseudo-handles from GetCurrentProcess() or GetCurrentThread().
    /// These return special sentinel values and must not be closed with CloseHandle.
    /// </summary>
    // --------------------------------------------------------------------------------
    class safe_object_handle
        : public std::unique_ptr<std::remove_pointer_t<HANDLE>, handle_deleter>
    {
        using base_type = std::unique_ptr<std::remove_pointer_t<HANDLE>, handle_deleter>;

    public:
        /// <summary>
        /// Constructs the object from an existing handle value.
        /// </summary>
        /// <param name="handle">Windows handle to wrap (nullptr for empty handle)</param>
        explicit safe_object_handle(HANDLE handle = nullptr) noexcept
            : base_type((handle == INVALID_HANDLE_VALUE) ? nullptr : handle)
        {
        }

        /// <summary>
        /// Deleted copy constructor (handles cannot be copied)
        /// </summary>
        safe_object_handle(const safe_object_handle& other) = delete;

        /// <summary>
        /// Move constructor
        /// </summary>
        /// <param name="other">Object instance to move from</param>
        safe_object_handle(safe_object_handle&& other) noexcept = default;

        /// <summary>
        /// Deleted copy assignment (handles cannot be copied)
        /// </summary>
        safe_object_handle& operator=(const safe_object_handle& other) = delete;

        /// <summary>
        /// Move assignment
        /// </summary>
        /// <param name="other">Object instance to move from</param>
        /// <returns>this object reference</returns>
        safe_object_handle& operator=(safe_object_handle&& other) noexcept = default;

        /// <summary>
        /// Default destructor (automatically closes handle via deleter)
        /// </summary>
        ~safe_object_handle() = default;

        /// <summary>
        /// Returns the stored handle value
        /// </summary>
        explicit operator HANDLE() const noexcept
        {
            return get();
        }

        /// <summary>
        /// Checks if the handle is valid (can be used in boolean context).
        /// Equivalent to calling valid().
        /// </summary>
        /// <returns>true if handle is valid, false if nullptr or INVALID_HANDLE_VALUE</returns>
        explicit operator bool() const noexcept
        {
            return valid();
        }

        /// <summary>
        /// Checks the stored handle value for validity.
        /// A valid handle is one that is neither nullptr nor INVALID_HANDLE_VALUE.
        /// </summary>
        /// <returns>true if valid, false otherwise</returns>
        [[nodiscard]] bool valid() const noexcept
        {
            const auto h = get();
            return h && (h != INVALID_HANDLE_VALUE);
        }
    };
}
#pragma warning( pop )