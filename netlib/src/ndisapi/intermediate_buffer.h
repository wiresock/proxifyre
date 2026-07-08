// ReSharper disable CppClangTidyBugproneCopyConstructorInit
#pragma once

namespace netlib::ndisapi
{
    /**
     * @class intermediate_buffer
     * @brief This class is a wrapper around the _INTERMEDIATE_BUFFER structure.
     *
     * @details This is a trivially copyable wrapper that provides type safety while maintaining
     * binary compatibility with _INTERMEDIATE_BUFFER. All copy/move operations are performed
     * using default (trivial) implementations.
     *
     * @note In user mode the m_hAdapter/m_qLink union is used as the adapter handle.
     * m_qLink is kernel-only queue metadata, so user-mode copies may preserve the
     * complete _INTERMEDIATE_BUFFER layout without maintaining list links.
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
         * @brief Copy constructor (defaulted for trivial copyability).
         */
        intermediate_buffer(const intermediate_buffer&) = default;

        /**
         * @brief Move constructor (defaulted for trivial copyability).
         */
        intermediate_buffer(intermediate_buffer&&) noexcept = default;

        /**
         * @brief Copy assignment operator (defaulted for trivial copyability).
         */
        intermediate_buffer& operator=(const intermediate_buffer&) = default;

        /**
         * @brief Move assignment operator (defaulted for trivial copyability).
         */
        intermediate_buffer& operator=(intermediate_buffer&&) noexcept = default;

        /**
         * @brief Constructor that initializes the object from a _INTERMEDIATE_BUFFER instance.
         * @param other The _INTERMEDIATE_BUFFER instance to initialize from.
         */
        explicit intermediate_buffer(const _INTERMEDIATE_BUFFER& other)
            : _INTERMEDIATE_BUFFER(other)
        {
            static_assert(sizeof(intermediate_buffer) == sizeof(_INTERMEDIATE_BUFFER),
                "Size of intermediate_buffer is not the same as _INTERMEDIATE_BUFFER");
            static_assert(std::is_trivially_copyable_v<intermediate_buffer>,
                "intermediate_buffer must be trivially copyable");
        }
    };

    // Compile-time verification
    static_assert(std::is_trivially_copyable_v<intermediate_buffer>,
        "intermediate_buffer must be trivially copyable");
}
