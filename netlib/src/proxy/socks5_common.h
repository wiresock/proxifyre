#pragma once

namespace proxy
{
#pragma pack(push,1) // Ensure tightly packed structures for protocol compliance

    // Constants defining SOCKS5 protocol specifics
    static constexpr uint8_t socks5_protocol_version = 5;
    static constexpr uint8_t socks5_username_auth_version = 1;
    static constexpr uint8_t socks5_username_max_length = 255;

    /**
     * @brief Represents the initial identification request from client to server in SOCKS5.
     * Contains the supported authentication methods.
     *
     * @tparam NumberOfMethods Number of authentication methods being sent (default is 1).
     */
    template <uint8_t NumberOfMethods = 1>
    struct socks5_ident_req
    {
        unsigned char version = socks5_protocol_version;  ///< SOCKS version (5)
        unsigned char number_of_methods = NumberOfMethods; ///< Number of supported auth methods
        unsigned char methods[NumberOfMethods]{};          ///< Array of supported auth method codes
    };

    /**
     * @brief Server response to client's identification request.
     * Specifies the selected authentication method.
     */
    struct socks5_ident_resp
    {
        unsigned char version = socks5_protocol_version; ///< SOCKS version (5)
        unsigned char method;                            ///< Chosen authentication method
    };

    /**
     * @brief Structure for username/password authentication as per RFC 1929.
     */
    struct socks5_username_auth
    {
        socks5_username_auth() = default;

        /**
         * @brief Constructor initializing the auth block with username and password.
         * @throws std::runtime_error if username or password exceeds 255 characters.
         */
        socks5_username_auth(const std::string& username, const std::string& password)
        {
            if (0 == init(username, password))
                throw std::runtime_error("SOCKS5: username or password length exceeds the limits");
        }

        /**
         * @brief Initializes the buffer with username and password in SOCKS5 format.
         *
         * Layout:
         *  - [version][ulen][uname][plen][pass]
         *
         * @return Length of the filled structure, or 0 on failure.
         */
        [[nodiscard]] uint32_t init(const std::string& username, const std::string& password)
        {
            if (username.length() > 255 || password.length() > 255)
                return 0;

            username_length = static_cast<unsigned char>(username.length());

            // Calculate where to store the password
            unsigned char* password_length_ptr = reinterpret_cast<unsigned char*>(username_reserved) + username_length;
            char* password_ptr = reinterpret_cast<char*>(password_length_ptr) + 1;

            strcpy_s(username_reserved, 255, username.c_str());

            *password_length_ptr = static_cast<unsigned char>(password.length());
            strcpy_s(password_ptr, 255, password.c_str());

            return (3 + static_cast<int>(username.length()) + static_cast<int>(password.length()));
        }

        unsigned char version = socks5_username_auth_version; ///< Version (1 for username/password)
        unsigned char username_length{};                      ///< Length of username
        char username_reserved[socks5_username_max_length + 1 + socks5_username_max_length]{};
        ///< Buffer to store username + [plen] + password (RFC1929-compliant)
    };

    /**
     * @brief Generic SOCKS5 request (e.g., CONNECT, BIND) with templated address type.
     *
     * @tparam T Address structure (IPv4, IPv6, or domain name)
     */
    template <typename T>
    struct socks5_req
    {
        unsigned char version = socks5_protocol_version; ///< SOCKS version
        unsigned char cmd{};                             ///< Command (CONNECT=1, BIND=2, UDP ASSOCIATE=3)
        unsigned char reserved{};                        ///< Reserved, always 0
        unsigned char address_type{};                    ///< Address type (IPv4, IPv6, Domain)
        T dest_address;                                  ///< Destination address (templated)
        unsigned short dest_port{};                      ///< Destination port (network byte order)
    };

    /**
     * @brief Generic SOCKS5 response structure for CONNECT/BIND replies.
     *
     * @tparam T Address structure (IPv4, IPv6, or domain)
     */
    template <typename T>
    struct socks5_resp
    {
        unsigned char version = socks5_protocol_version; ///< SOCKS version
        unsigned char reply{};                           ///< Reply code (0x00 = success, others = error)
        unsigned char reserved{};                        ///< Reserved, always 0
        unsigned char address_type{};                    ///< Address type
        T bind_address;                                  ///< Server-bound address
        unsigned short bind_port{};                      ///< Server-bound port
    };

    /**
     * @brief Structure for SOCKS5 UDP header (as per RFC 1928).
     *
     * @tparam T Address type
     */
    template <typename T>
    struct socks5_udp_header
    {
        unsigned short reserved;     ///< Reserved field, must be 0x0000
        unsigned char fragment;      ///< Fragment number (0 unless fragmentation is used)
        unsigned char address_type;  ///< Address type (IPv4, IPv6, Domain)
        T dest_address;              ///< Destination address
        unsigned short dest_port;    ///< Destination port
    };

#pragma pack(pop)

    /**
     * @brief Context for SOCKS5 negotiation, optionally including authentication credentials.
     *
     * Inherits from `negotiate_context<T>`, likely a base class holding remote address/port.
     *
     * @tparam T Address type (e.g., IPv4, IPv6 struct)
     */
    template <typename T>
    struct socks5_negotiate_context final : negotiate_context<T>
    {
        /**
         * @brief Constructor for anonymous SOCKS5 negotiation (no auth).
         */
        socks5_negotiate_context(const T& remote_address, uint16_t remote_port)
            : negotiate_context<T>(remote_address, remote_port)
        {
        }

        /**
         * @brief Constructor for negotiation with optional auth parameters.
         */
        socks5_negotiate_context(const T& remote_srv_address, uint16_t remote_srv_port,
            std::optional<std::string> socks5_username, std::optional<std::string> socks5_password)
            : negotiate_context<T>(remote_srv_address, remote_srv_port),
            socks5_username(std::move(socks5_username)),
            socks5_password(std::move(socks5_password))
        {
        }

        /**
         * @brief Constructor for negotiation with mandatory username/password.
         */
        socks5_negotiate_context(const T& remote_address, uint16_t remote_port,
            std::string socks5_username, std::string socks5_password)
            : negotiate_context<T>(remote_address, remote_port),
            socks5_username(std::move(socks5_username)),
            socks5_password(std::move(socks5_password))
        {
        }

        std::optional<std::string> socks5_username{ std::nullopt }; ///< Optional username
        std::optional<std::string> socks5_password{ std::nullopt }; ///< Optional password
    };
}
