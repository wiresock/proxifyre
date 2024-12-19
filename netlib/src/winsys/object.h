#pragma once

#pragma warning( push )
#pragma warning( disable : 26456 )

namespace winsys
{
    // --------------------------------------------------------------------------------
    /// <summary>
    /// simple wrapper class for Windows handle
    /// </summary>
    // --------------------------------------------------------------------------------
    class safe_object_handle : public std::unique_ptr<std::remove_pointer_t<HANDLE>, void(*)(HANDLE)>
    {
    public:
        /// <summary>
        /// Constructs the object from the existing handle value
        /// </summary>
        /// <param name="handle"></param>
        // ReSharper disable once CppParameterMayBeConst
        explicit safe_object_handle(HANDLE handle) noexcept: unique_ptr(handle, &safe_object_handle::close)
        {
        }

        /// <summary>
        /// Deleted copy constructor
        /// </summary>
        safe_object_handle(const safe_object_handle& other) = delete;

        /// <summary>
        /// Move constructor
        /// </summary>
        /// <param name="other">Object instance to move from</param>
        safe_object_handle(safe_object_handle&& other) noexcept
            : std::unique_ptr<std::remove_pointer_t<HANDLE>, void(*)(HANDLE)>{std::move(other)}
        {
        }

        /// <summary>
        /// Deleted copy assignment
        /// </summary>
        safe_object_handle& operator=(const safe_object_handle& other) = delete;

        /// <summary>
        /// Move assignment
        /// </summary>
        /// <param name="other">Object instance to move from</param>
        /// <returns>this object reference</returns>
        safe_object_handle& operator=(safe_object_handle&& other) noexcept
        {
            if (this == &other)
                return *this;
            std::unique_ptr<std::remove_pointer_t<HANDLE>, void(*)(HANDLE)>::operator =(std::move(other));
            return *this;
        }

        /// <summary>
        /// Default destructor
        /// </summary>
        /// <returns></returns>
        ~safe_object_handle() = default;

        /// <summary>
        /// Returns the stored handle value
        /// </summary>
        explicit operator HANDLE() const noexcept
        {
            return get();
        }

        /// <summary>
        /// Checks the stored handle value for validity
        /// </summary>
        /// <returns>true if valid, false otherwise</returns>
        [[nodiscard]] bool valid() const noexcept
        {
            return ((get() != INVALID_HANDLE_VALUE) && (get() != nullptr));
        }

    private:
        /// <summary>
        /// deleter for the stored windows handle (calls CloseHandle for the handle)
        /// </summary>
        /// <param name="handle">windows handle to close</param>
        // ReSharper disable once CppParameterMayBeConst
        static void close(HANDLE handle) noexcept
        {
            if ((handle != INVALID_HANDLE_VALUE) && (handle != nullptr))
                CloseHandle(handle);
        }
    };
}
#pragma warning( pop )
