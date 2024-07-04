// ReSharper disable CppClangTidyBugproneCopyConstructorInit
#pragma once

namespace ndisapi
{
    /**
     * @class intermediate_buffer
     * @brief This class is a wrapper around the _INTERMEDIATE_BUFFER structure.
     *
     * @details It provides constructors for default initialization, copy initialization, move initialization,
     * and initialization from _INTERMEDIATE_BUFFER. It also provides copy and move assignment operators.
     * The class contains private helper methods for copy and move operations.
     */
    class intermediate_buffer : public _INTERMEDIATE_BUFFER {
    public:
        /**
         * @brief Default constructor.
         */
        intermediate_buffer()
        {
            static_assert(sizeof(intermediate_buffer) == sizeof(_INTERMEDIATE_BUFFER),
                "Size of intermediate_buffer is not the same as _INTERMEDIATE_BUFFER");
        }
        /**
         * @brief Destructor.
         */
        ~intermediate_buffer() = default;
        /**
         * @brief Constructor that initializes the object from a _INTERMEDIATE_BUFFER instance.
         * @param other The _INTERMEDIATE_BUFFER instance to initialize from.
         */
        explicit intermediate_buffer(const _INTERMEDIATE_BUFFER& other) {
            assign(other);
        }
        /**
         * @brief Copy constructor.
         * @param other The intermediate_buffer instance to copy from.
         */
        intermediate_buffer(const intermediate_buffer& other)
        {
            assign(other);
        }
        /**
         * @brief Move constructor.
         * @param other The intermediate_buffer instance to move from.
         */
        intermediate_buffer(intermediate_buffer&& other) noexcept {
            move(std::move(other));
        }
        /**
         * @brief Copy assignment operator.
         * @param other The intermediate_buffer instance to copy from.
         * @return A reference to the current instance.
         */
        intermediate_buffer& operator=(const intermediate_buffer& other) {
            if (this != &other) {
                assign(other);
            }
            return *this;
        }
        /**
         * @brief Move assignment operator.
         * @param other The intermediate_buffer instance to move from.
         * @return A reference to the current instance.
         */
        intermediate_buffer& operator=(intermediate_buffer&& other) noexcept {
            if (this != &other) {
                move(std::move(other));
            }
            return *this;
        }
    private:
        /**
         * @brief Helper method for copy operations.
         * @tparam T The type of the other object (can be intermediate_buffer or _INTERMEDIATE_BUFFER).
         * @param other The object to copy from.
         */
        template<typename T>
        void assign(const T& other) {
            m_hAdapter = other.m_hAdapter;
            m_dwDeviceFlags = other.m_dwDeviceFlags;
            m_Length = other.m_Length;
            m_Flags = other.m_Flags;
            m_8021q = other.m_8021q;
            m_FilterID = other.m_FilterID;
            std::copy_n(other.m_Reserved, 4, m_Reserved);
            std::copy_n(other.m_IBuffer, other.m_Length, m_IBuffer);
        }
        /**
         * @brief Helper method for move operations.
         * @param other The object to move from.
         */
        void move(intermediate_buffer&& other) noexcept {
            m_hAdapter = other.m_hAdapter;
            m_dwDeviceFlags = other.m_dwDeviceFlags;
            m_Length = other.m_Length;
            m_Flags = other.m_Flags;
            m_8021q = other.m_8021q;
            m_FilterID = other.m_FilterID;
            std::copy_n(other.m_Reserved, 4, m_Reserved);
            std::copy_n(other.m_IBuffer, other.m_Length, m_IBuffer);
        }
    };
}

