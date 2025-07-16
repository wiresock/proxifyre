#pragma once

namespace proxy
{
    /**
     * @brief Helper variable template for static_assert in templates.
     * Always evaluates to false.
     */
    template <typename...>
    constexpr bool false_v = false;

    /**
     * @enum proxy_io_operation
     * @brief Enumerates the types of I/O operations used in the proxy.
     *
     * - relay_io_read:      Read operation for relaying data.
     * - relay_io_write:     Write operation for relaying data.
     * - negotiate_io_read:  Read operation during connection negotiation.
     * - negotiate_io_write: Write operation during connection negotiation.
     * - inject_io_write:    Write operation for injecting data.
     */
    enum class proxy_io_operation : uint8_t
    {
        relay_io_read = 0,      ///< Read operation for relaying data.
        relay_io_write = 1,     ///< Write operation for relaying data.
        negotiate_io_read = 2,  ///< Read operation during negotiation.
        negotiate_io_write = 3, ///< Write operation during negotiation.
        inject_io_write = 4     ///< Write operation for injecting data.
    };

    // --------------------------------------------------------------------------------
    /// <summary>
    /// Used to pass data required to negotiate connection to the remote proxy
    /// </summary>
    // --------------------------------------------------------------------------------
    /**
     * @struct negotiate_context
     * @brief Holds data required to negotiate a connection to a remote proxy.
     *
     * @tparam T The type representing the remote address (e.g., IP address type).
     *
     * Contains the remote address and port, and provides copy/move constructors and assignment operators.
     */
    template <typename T>
    struct negotiate_context
    {
        /**
         * @brief Constructs a negotiate_context with the given address and port.
         * @param remote_address The remote address.
         * @param remote_port The remote port.
         */
        negotiate_context(const T& remote_address, const uint16_t remote_port)
            : remote_address(remote_address),
            remote_port(remote_port)
        {
        }

        /**
         * @brief Virtual destructor for safe inheritance.
         */
        virtual ~negotiate_context() = default;

        /**
         * @brief Copy constructor.
         * @param other The context to copy from.
         */
        negotiate_context(const negotiate_context& other)
            : remote_address(other.remote_address),
            remote_port(other.remote_port)
        {
        }

        /**
         * @brief Move constructor.
         * @param other The context to move from.
         */
        negotiate_context(negotiate_context&& other) noexcept
            : remote_address(std::move(other.remote_address)),
            remote_port(other.remote_port)
        {
        }

        /**
         * @brief Copy assignment operator.
         * @param other The context to copy from.
         * @return Reference to this object.
         */
        negotiate_context& operator=(const negotiate_context& other)
        {
            if (this == &other)
                return *this;

            remote_address = other.remote_address;
            remote_port = other.remote_port;
            return *this;
        }

        /**
         * @brief Move assignment operator.
         * @param other The context to move from.
         * @return Reference to this object.
         */
        negotiate_context& operator=(negotiate_context&& other) noexcept
        {
            if (this == &other)
                return *this;

            remote_address = std::move(other.remote_address);
            remote_port = other.remote_port;
            return *this;
        }

        /**
         * @brief The remote address for negotiation.
         */
        T remote_address;

        /**
         * @brief The remote port for negotiation.
         */
        uint16_t remote_port;
    };
}