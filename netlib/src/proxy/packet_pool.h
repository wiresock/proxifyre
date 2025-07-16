#pragma once
namespace proxy
{
    // --------------------------------------------------------------------------------
    /// <summary>
    /// Template wrapper for WSABUF.
    /// Represents a network packet buffer of fixed size, providing
    /// memory management and access utilities.
    /// </summary>
    /// <typeparam name="Size">The size of the buffer in bytes.</typeparam>
    // --------------------------------------------------------------------------------
    template <uint32_t Size>
    struct net_packet : WSABUF
    {
        /// <summary>
        /// Constructs a net_packet and allocates internal storage.
        /// </summary>
        net_packet() : _WSABUF(), data_(std::make_unique<storage_type_t>())
        {
            buf = reinterpret_cast<char*>(data_.get());
            len = Size;
        }

        /// <summary>
        /// Returns a pointer to the internal data buffer.
        /// </summary>
        /// <returns>Pointer to the buffer.</returns>
        char* data()
        {
            return reinterpret_cast<char*>(data_.get());
        }

        /// <summary>
        /// Gets the maximum size of the buffer.
        /// </summary>
        /// <returns>Maximum buffer size in bytes.</returns>
        [[nodiscard]] uint32_t max_size() const
        {
            return max_size_;
        }

    private:
        using storage_type_t = std::aligned_storage_t<Size>;
        std::unique_ptr<storage_type_t> data_;
        uint32_t max_size_{ Size };
    };

    /// <summary>
    /// Alias for a large network packet buffer (default size: 65536 bytes).
    /// </summary>
    using net_packet_t = net_packet<256 * 256>;

    /**
     * @class packet_pool
     * @brief Memory pool for efficient allocation and reuse of network packet buffers.
     *
     * Provides allocation and deallocation of net_packet_t objects of various sizes.
     * Maintains internal pools for different buffer sizes to minimize heap allocations
     * and improve performance in high-throughput network applications.
     */
    class packet_pool
    {
    public:
        /**
         * @brief Constructs a packet_pool with a specified pool size limit.
         * @param pool_size Maximum number of buffers to keep in each internal pool.
         */
        explicit packet_pool(const uint32_t pool_size = 100) : pool_count_limit_{ pool_size }
        {
        }

        /**
         * @brief Allocates a network packet buffer of at least the requested size.
         *
         * Returns a unique_ptr to a net_packet_t of the appropriate size class.
         * If the requested size exceeds the maximum allowed, returns nullptr.
         *
         * @param size The minimum required buffer size in bytes.
         * @return Unique pointer to a net_packet_t, or nullptr on failure.
         */
        std::unique_ptr<net_packet_t> allocate(const uint32_t size)
        {
            if (size > 256 * 256)
                return nullptr;

            std::lock_guard<std::mutex> lock(lock_);

            if (size <= 32)
            {
                if (!p_32_b_.empty())
                {
                    auto packet = std::move(p_32_b_.top());
                    p_32_b_.pop();
                    return std::unique_ptr<net_packet_t>(reinterpret_cast<net_packet_t*>(packet.release()));
                }

                try
                {
                    auto packet = std::make_unique<net_packet<32>>();
                    return std::unique_ptr<net_packet_t>(reinterpret_cast<net_packet_t*>(packet.release()));
                }
                catch (std::bad_alloc&)
                {
                    return nullptr;
                }
            }

            if (size <= 64)
            {
                if (!p_64_b_.empty())
                {
                    auto packet = std::move(p_64_b_.top());
                    p_64_b_.pop();
                    return std::unique_ptr<net_packet_t>(reinterpret_cast<net_packet_t*>(packet.release()));
                }
                try
                {
                    auto packet = std::make_unique<net_packet<64>>();
                    return std::unique_ptr<net_packet_t>(reinterpret_cast<net_packet_t*>(packet.release()));
                }
                catch (std::bad_alloc&)
                {
                    return nullptr;
                }
            }

            if (size <= 128)
            {
                if (!p_128_b_.empty())
                {
                    auto packet = std::move(p_128_b_.top());
                    p_128_b_.pop();
                    return std::unique_ptr<net_packet_t>(reinterpret_cast<net_packet_t*>(packet.release()));
                }
                try
                {
                    auto packet = std::make_unique<net_packet<128>>();
                    return std::unique_ptr<net_packet_t>(reinterpret_cast<net_packet_t*>(packet.release()));
                }
                catch (std::bad_alloc&)
                {
                    return nullptr;
                }
            }

            if (size <= 256)
            {
                if (!p_256_b_.empty())
                {
                    auto packet = std::move(p_256_b_.top());
                    p_256_b_.pop();
                    return std::unique_ptr<net_packet_t>(reinterpret_cast<net_packet_t*>(packet.release()));
                }
                try
                {
                    auto packet = std::make_unique<net_packet<256>>();
                    return std::unique_ptr<net_packet_t>(reinterpret_cast<net_packet_t*>(packet.release()));
                }
                catch (std::bad_alloc&)
                {
                    return nullptr;
                }
            }

            if (size <= 512)
            {
                if (!p_512_b_.empty())
                {
                    auto packet = std::move(p_512_b_.top());
                    p_512_b_.pop();
                    return std::unique_ptr<net_packet_t>(reinterpret_cast<net_packet_t*>(packet.release()));
                }
                try
                {
                    auto packet = std::make_unique<net_packet<512>>();
                    return std::unique_ptr<net_packet_t>(reinterpret_cast<net_packet_t*>(packet.release()));
                }
                catch (std::bad_alloc&)
                {
                    return nullptr;
                }
            }

            if (size <= 1024)
            {
                if (!p_1024_b_.empty())
                {
                    auto packet = std::move(p_1024_b_.top());
                    p_1024_b_.pop();
                    return std::unique_ptr<net_packet_t>(reinterpret_cast<net_packet_t*>(packet.release()));
                }
                try
                {
                    auto packet = std::make_unique<net_packet<1024>>();
                    return std::unique_ptr<net_packet_t>(reinterpret_cast<net_packet_t*>(packet.release()));
                }
                catch (std::bad_alloc&)
                {
                    return nullptr;
                }
            }

            if (size <= 2048)
            {
                if (!p_2048_b_.empty())
                {
                    auto packet = std::move(p_2048_b_.top());
                    p_2048_b_.pop();
                    return std::unique_ptr<net_packet_t>(reinterpret_cast<net_packet_t*>(packet.release()));
                }
                try
                {
                    auto packet = std::make_unique<net_packet<2048>>();
                    return std::unique_ptr<net_packet_t>(reinterpret_cast<net_packet_t*>(packet.release()));
                }
                catch (std::bad_alloc&)
                {
                    return nullptr;
                }
            }

            if (!p_max_b_.empty())
            {
                auto packet = std::move(p_max_b_.top());
                p_max_b_.pop();
                return std::unique_ptr<net_packet_t>(packet.release());
            }
            try
            {
                auto packet = std::make_unique<net_packet<256 * 256>>();
                return std::unique_ptr<net_packet_t>(packet.release());
            }
            catch (std::bad_alloc&)
            {
                return nullptr;
            }
        }

        /**
         * @brief Returns a packet buffer to the pool for reuse.
         *
         * The buffer is placed in the appropriate internal pool based on its size.
         * If the pool for that size is full, the buffer is destroyed.
         *
         * @param packet Unique pointer to the packet buffer to free.
         */
        void free(std::unique_ptr<net_packet_t> packet)
        {
            std::lock_guard<std::mutex> lock(lock_);

            switch (packet->max_size())
            {
            case 32:
                if (p_32_b_.size() < pool_count_limit_)
                {
                    p_32_b_.push(std::unique_ptr<net_packet<32>>(reinterpret_cast<net_packet<32>*>(packet.release())));
                }
                break;
            case 64:
                if (p_64_b_.size() < pool_count_limit_)
                {
                    p_64_b_.push(std::unique_ptr<net_packet<64>>(reinterpret_cast<net_packet<64>*>(packet.release())));
                }
                break;
            case 128:
                if (p_128_b_.size() < pool_count_limit_)
                {
                    p_128_b_.push(
                        std::unique_ptr<net_packet<128>>(reinterpret_cast<net_packet<128>*>(packet.release())));
                }
                break;
            case 256:
                if (p_256_b_.size() < pool_count_limit_)
                {
                    p_256_b_.push(
                        std::unique_ptr<net_packet<256>>(reinterpret_cast<net_packet<256>*>(packet.release())));
                }
                break;
            case 512:
                if (p_512_b_.size() < pool_count_limit_)
                {
                    p_512_b_.push(
                        std::unique_ptr<net_packet<512>>(reinterpret_cast<net_packet<512>*>(packet.release())));
                }
                break;
            case 1024:
                if (p_1024_b_.size() < pool_count_limit_)
                {
                    p_1024_b_.push(
                        std::unique_ptr<net_packet<1024>>(reinterpret_cast<net_packet<1024>*>(packet.release())));
                }
                break;
            case 2048:
                if (p_2048_b_.size() < pool_count_limit_)
                {
                    p_2048_b_.push(
                        std::unique_ptr<net_packet<2048>>(reinterpret_cast<net_packet<2048>*>(packet.release())));
                }
                break;
            case 256 * 256:
                if (p_max_b_.size() < pool_count_limit_)
                {
                    p_max_b_.push(std::unique_ptr<net_packet<256 * 256>>(packet.release()));
                }
                break;
            default:
                break;
            }
        }

        /**
         * @brief Gets the current pool size limit for each buffer size.
         * @return The pool size limit.
         */
        uint32_t get_pool_size_limit() const
        {
            return pool_count_limit_;
        }

        /**
         * @brief Sets a new pool size limit and resets all internal pools.
         * @param pool_size_limit The new pool size limit.
         */
        void set_pool_size_limit(const uint32_t pool_size_limit)
        {
            reset();
            pool_count_limit_ = pool_size_limit;
        }

        /**
         * @brief Clears all internal buffer pools, releasing all stored buffers.
         */
        void reset()
        {
            std::lock_guard<std::mutex> lock(lock_);

            std::stack<std::unique_ptr<net_packet<32>>>().swap(p_32_b_);
            std::stack<std::unique_ptr<net_packet<64>>>().swap(p_64_b_);
            std::stack<std::unique_ptr<net_packet<128>>>().swap(p_128_b_);
            std::stack<std::unique_ptr<net_packet<256>>>().swap(p_256_b_);
            std::stack<std::unique_ptr<net_packet<512>>>().swap(p_512_b_);
            std::stack<std::unique_ptr<net_packet<1024>>>().swap(p_1024_b_);
            std::stack<std::unique_ptr<net_packet<2048>>>().swap(p_2048_b_);
            std::stack<std::unique_ptr<net_packet<256 * 256>>>().swap(p_max_b_);
        }

    private:
        /// <summary>Stack of 32-byte packet buffers.</summary>
        std::stack<std::unique_ptr<net_packet<32>>> p_32_b_;
        /// <summary>Stack of 64-byte packet buffers.</summary>
        std::stack<std::unique_ptr<net_packet<64>>> p_64_b_;
        /// <summary>Stack of 128-byte packet buffers.</summary>
        std::stack<std::unique_ptr<net_packet<128>>> p_128_b_;
        /// <summary>Stack of 256-byte packet buffers.</summary>
        std::stack<std::unique_ptr<net_packet<256>>> p_256_b_;
        /// <summary>Stack of 512-byte packet buffers.</summary>
        std::stack<std::unique_ptr<net_packet<512>>> p_512_b_;
        /// <summary>Stack of 1024-byte packet buffers.</summary>
        std::stack<std::unique_ptr<net_packet<1024>>> p_1024_b_;
        /// <summary>Stack of 2048-byte packet buffers.</summary>
        std::stack<std::unique_ptr<net_packet<2048>>> p_2048_b_;
        /// <summary>Stack of max-size packet buffers (65536 bytes).</summary>
        std::stack<std::unique_ptr<net_packet<256 * 256>>> p_max_b_;

        /// <summary>Mutex for synchronizing access to all buffer pools.</summary>
        std::mutex lock_;

        /// <summary>Maximum number of buffers to keep in each pool.</summary>
        std::atomic_uint32_t pool_count_limit_;
    };
}