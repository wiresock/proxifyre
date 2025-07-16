#pragma once

#include <boost/pool/object_pool.hpp>

namespace ndisapi
{
    /// <summary>
    /// A singleton class that manages a pool of intermediate_buffer objects.
    /// </summary>
    class intermediate_buffer_pool {
    public:
        /// <summary>
        /// Deleted copy constructor to prevent copying.
        /// </summary>
        intermediate_buffer_pool(const intermediate_buffer_pool&) = delete;

        /// <summary>
        /// Deleted copy assignment operator to prevent copying.
        /// </summary>
        intermediate_buffer_pool& operator=(const intermediate_buffer_pool&) = delete;

        /// <summary>
        /// Accessor for the singleton instance.
        /// </summary>
        /// <returns>A reference to the singleton instance of intermediate_buffer_pool.</returns>
        static intermediate_buffer_pool& instance() {
            static intermediate_buffer_pool instance;
            return instance;
        }

        /// <summary>
        /// Custom deleter for unique_ptr.
        /// </summary>
        struct deleter {
            /// <summary>
            /// Deletes the intermediate_buffer object.
            /// </summary>
            /// <param name="ptr">Pointer to the intermediate_buffer object to be deleted.</param>
            void operator()(intermediate_buffer* ptr) const {
                instance().pool_.destroy(ptr);
            }
        };

        using intermediate_buffer_ptr = std::unique_ptr<intermediate_buffer, deleter>;

        /// <summary>
        /// Allocates a new intermediate_buffer object from the pool.
        /// </summary>
        /// <returns>A unique_ptr to the allocated intermediate_buffer object, or nullptr if allocation fails.</returns>
        intermediate_buffer_ptr allocate() {
            try {
                auto* raw_ptr = pool_.construct(); // This might throw
                std::fill_n(reinterpret_cast<char*>(raw_ptr), offsetof(_INTERMEDIATE_BUFFER, m_IBuffer), 0);
                return intermediate_buffer_ptr(raw_ptr, deleter{});
            }
            catch (...) {
                return nullptr; // Return a null std::unique_ptr
            }
        }

        /// <summary>
        /// Allocates a new intermediate_buffer object from the pool and initializes it with the provided source.
        /// </summary>
        /// <param name="source">The source intermediate_buffer object to copy from.</param>
        /// <returns>A unique_ptr to the allocated and initialized intermediate_buffer object, or nullptr if allocation fails.</returns>
        intermediate_buffer_ptr allocate(const intermediate_buffer& source) {
            auto buffer = allocate(); // Allocate a new buffer

            if (buffer) { // Check if allocation was successful
                *buffer = source; // Use the copy assignment operator of intermediate_buffer
            }
            return buffer; // Return the allocated buffer or nullptr if allocation failed
        }

        /// <summary>
        /// Default destructor.
        /// </summary>
        ~intermediate_buffer_pool() = default;

        /// <summary>
        /// Default move constructor.
        /// </summary>
        intermediate_buffer_pool(intermediate_buffer_pool&&) noexcept = delete;

        /// <summary>
        /// Default move assignment operator.
        /// </summary>
        intermediate_buffer_pool& operator=(intermediate_buffer_pool&&) noexcept = delete;

    private:
        /// <summary>
        /// Private constructor for singleton.
        /// </summary>
        /// <param name="initial_size">The initial size of the pool.</param>
        explicit intermediate_buffer_pool(const size_t initial_size = 32)
            : pool_(initial_size) {
        }

        boost::object_pool<intermediate_buffer> pool_; ///< The pool of intermediate_buffer objects.
    };
}