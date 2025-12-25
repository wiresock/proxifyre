#pragma once

namespace netlib::winsys
{
    // --------------------------------------------------------------------------------
    /// <summary>
    /// Represents a thread pool for the derived CRTP classes.
    /// \tparam T CRTP derived class should provide start_thread() and stop_thread() routines.
    ///
    /// CONCURRENCY CONTRACT:
    /// - Do NOT call start_thread_pool() and stop_thread_pool() concurrently from
    ///   different threads. External synchronization is required for start/stop.
    /// - Concurrent calls to start_thread_pool() are safe in the sense that only
    ///   one caller will actually start the pool; the rest will be no-ops.
    /// - Concurrent calls to stop_thread_pool() are safe; only the first will
    ///   perform shutdown, subsequent calls are no-ops.
    /// </summary>
    // --------------------------------------------------------------------------------
    template <typename T>
    class thread_pool  // NOLINT(clang-diagnostic-padded)
    {
        friend T; // Allow derived class to access private members

        /// <summary>working threads container</summary>
        std::vector<std::thread> threads_;

    protected:
        /// <summary>number of concurrent threads in the pool</summary>
        size_t concurrent_threads_;
        /// <summary>thread pool termination flag</summary>
        std::atomic_bool active_{ false };

    private:
        // ********************************************************************************
        /// <summary>
        /// Initializes thread_pool with specified number of concurrent threads.
        /// </summary>
        /// <param name="concurrent_threads">Number of concurrent threads in the pool
        /// (0 means std::thread::hardware_concurrency()).</param>
        // ********************************************************************************
        explicit thread_pool(const size_t concurrent_threads = 0) noexcept
            : concurrent_threads_{ (concurrent_threads == 0)
                                       ? std::thread::hardware_concurrency()
                                       : concurrent_threads }
        {
        }

    public:
        // Delete copy and move operations (moving a pool whose threads capture `this` is unsafe)
        thread_pool(const thread_pool&) = delete;  // NOLINT(bugprone-crtp-constructor-accessibility)
        thread_pool& operator=(const thread_pool&) = delete;
        thread_pool(thread_pool&&) = delete;  // NOLINT(bugprone-crtp-constructor-accessibility)
        thread_pool& operator=(thread_pool&&) = delete;

        ~thread_pool()
        {
            // RAII: best-effort stop; swallow any exceptions, but log in debug.
            if (active_.load(std::memory_order_acquire))
            {
                try
                {
                    // See concurrency contract in class documentation:
                    // this destructor must not race with external start/stop.
                    stop_thread_pool();
                }
                catch (const std::exception& e)
                {
                    try
                    {
                        OutputDebugStringA(std::format("thread_pool: exception during stop_thread_pool in destructor: {}\n", e.what()).c_str());
                    }
                    catch (...)
                    {
                        OutputDebugStringA("thread_pool: exception during stop_thread_pool in destructor (format failed)\n");
                    }
                }
                catch (...)
                {
                    OutputDebugStringA("thread_pool: unknown exception during stop_thread_pool in destructor\n");
                }
            }
        }

        // ********************************************************************************
        /// <summary>
        /// Starts threads in the pool if not already started.
        ///
        /// NOTE: This function must not be called concurrently with stop_thread_pool()
        /// from different threads. External synchronization is required for start/stop.
        /// </summary>
        /// <exception cref="std::system_error">Thrown if thread creation fails.
        /// On failure, state is rolled back to allow retry.</exception>
        // ********************************************************************************
        void start_thread_pool()
        {
            // Only one caller wins the transition false -> true
            // Use acq_rel for consistency with stop_thread_pool:
            // - acquire: see any prior state from a previous stop
            // - release: publish our start to other threads
            if (bool expected = false; !active_.compare_exchange_strong(
                expected, true,
                std::memory_order_acq_rel,
                std::memory_order_acquire))
            {
                return; // already started
            }

            // Reserve space to avoid reallocations during push_back
            threads_.reserve(concurrent_threads_ * 2);

            // Create twice as many threads as may run concurrently
            // (beneficial for I/O-bound work where threads frequently block)
            const auto worker_count = concurrent_threads_ * 2;

            try
            {
                for (size_t i = 0; i < worker_count; ++i)
                {
                    threads_.emplace_back(&T::start_thread, static_cast<T*>(this));
                }
            }
            catch (...)
            {
                // Thread creation failed - roll back to consistent state
                // Signal threads to stop via the active flag
                // Use release to ensure threads see consistent state before checking active_
                active_.store(false, std::memory_order_release);

                // Wake up any threads that may be blocked waiting for work
                // (mirrors stop_thread_pool() behavior to avoid deadlock on join)
                const auto created_count = threads_.size();
                for (size_t i = 0; i < created_count; ++i)
                {
                    static_cast<T*>(this)->stop_thread();
                }

                // Join any threads that were successfully created
                for (auto& thread : threads_)
                {
                    if (thread.joinable())
                        thread.join();
                }

                // Clear the partial thread list
                threads_.clear();

                // Rethrow to inform caller of failure
                throw;
            }
        }

        // ********************************************************************************
        /// <summary>
        /// Stops threads in the pool using CRTP derived class stop_thread() method.
        ///
        /// NOTE: This function must not be called concurrently with start_thread_pool()
        /// from different threads. External synchronization is required for start/stop.
        /// </summary>
        // ********************************************************************************
        void stop_thread_pool()
        {
            // Only first caller that sees true does the stop work
            if (!active_.exchange(false, std::memory_order_acq_rel))
                return;

            const auto thread_count = threads_.size();

            // Signal each thread individually to ensure all threads are woken
            for (size_t i = 0; i < thread_count; ++i)
            {
                static_cast<T&>(*this).stop_thread();
            }

            // Wait for all threads to complete
            for (auto& thread : threads_)
            {
                if (thread.joinable())
                    thread.join();
            }

            // Clear the thread vector after all joined
            threads_.clear();
        }

        // ********************************************************************************
        /// <summary>
        /// Returns the number of concurrent threads in the pool.
        /// </summary>
        // ********************************************************************************
        [[nodiscard]] size_t get_concurrent_threads() const noexcept
        {
            return concurrent_threads_;
        }

        // ********************************************************************************
        /// <summary>
        /// Returns the total number of worker threads (typically 2x concurrent).
        /// </summary>
        // ********************************************************************************
        [[nodiscard]] size_t get_worker_threads() const noexcept
        {
            return concurrent_threads_ * 2;
        }
    };

    // --------------------------------------------------------------------------------
    /// <summary>
    /// Windows I/O completion port wrapper with internal thread pool.
    ///
    /// CONCURRENCY CONTRACT:
    /// - Follows the same start/stop constraints as thread_pool (see thread_pool docs).
    /// - Handler registration/unregistration is thread-safe.
    ///
    /// USAGE NOTES:
    /// - After construction, callers should check valid() to ensure IOCP was created successfully.
    /// - On 32-bit systems, completion keys may theoretically wrap around after ~4 billion associations.
    ///   For long-running services, consider monitoring handler count and restarting if needed.
    /// </summary>
    // --------------------------------------------------------------------------------
    class io_completion_port final : public safe_object_handle, public thread_pool<io_completion_port>
    {
        friend thread_pool;

        using mutex_type = std::shared_mutex;
        using read_lock = std::shared_lock<mutex_type>;
        using write_lock = std::unique_lock<mutex_type>;

    public:
        // ********************************************************************************
        /// <summary>
        /// Type of completion key callback.
        /// Signature: bool(DWORD num_bytes, OVERLAPPED* overlapped, BOOL ok).
        /// </summary>
        // ********************************************************************************
        using callback_t = bool(DWORD, OVERLAPPED*, BOOL);

        io_completion_port(const io_completion_port& other) = delete;
        io_completion_port& operator=(const io_completion_port& other) = delete;

        // Moving a live IOCP with a thread pool that captures `this` is dangerous; forbid it
        io_completion_port(io_completion_port&&) = delete;
        io_completion_port& operator=(io_completion_port&&) = delete;

    private:
        /// <summary>synchronization lock for handlers below (accessed concurrently)</summary>
        mutable mutex_type handlers_lock_;

        /// <summary>callback handlers storage keyed by IOCP completion key</summary>
        std::unordered_map<ULONG_PTR, std::function<callback_t>> handlers_;

        /// <summary>monotonically increasing key generator (0 reserved for internal wake-up)</summary>
        std::atomic<ULONG_PTR> next_key_{ 1 };

        /// <summary>timeout for GetQueuedCompletionStatus (allows responsive shutdown)</summary>
        static constexpr DWORD shutdown_timeout_ms = 100;

        // ********************************************************************************
        /// <summary>
        /// Working thread routine (calls stored functions by the I/O completion key).
        /// </summary>
        // ********************************************************************************
        void start_thread() const
        {
            while (active_.load(std::memory_order_acquire))
            {
                DWORD       num_bytes = 0;
                ULONG_PTR   completion_key = 0;
                OVERLAPPED* overlapped_ptr = nullptr;

                const auto ok =
                    GetQueuedCompletionStatus(get(), &num_bytes, &completion_key, &overlapped_ptr, shutdown_timeout_ms);

                // Check after the wait as well, to exit promptly once stopped
                if (!active_.load(std::memory_order_acquire))
                    break;

                if (!ok)
                {
                    const auto err = GetLastError();

                    // Genuine timeout: no completion to dispatch
                    if (err == WAIT_TIMEOUT &&
                        overlapped_ptr == nullptr &&
                        completion_key == 0 &&
                        num_bytes == 0)
                    {
                        continue;
                    }

                    // Non-timeout error with no overlapped -> IOCP issue, can't dispatch
                    if (overlapped_ptr == nullptr)
                    {
#ifdef _DEBUG
                        try
                        {
                            OutputDebugStringA(std::format("GetQueuedCompletionStatus failed: {}\n", err).c_str());
                        }
                        catch (...)
                        {
                            OutputDebugStringA("GetQueuedCompletionStatus failed (format error)\n");
                        }
#endif
                        continue;
                    }

                    // Otherwise (overlapped_ptr != nullptr), fall through and dispatch
                    // with ok == FALSE so handler can inspect GetLastError() if needed.
                }

                // Key == 0 is used as a wake-up / stop signal; do not dispatch a handler
                if (completion_key == 0)
                    continue;

                std::function<callback_t> handler;

                {
                    read_lock lock(handlers_lock_);
                    const auto it = handlers_.find(completion_key);
                    if (it != handlers_.end())
                    {
                        // Copy handler under lock to use it safely outside
                        handler = it->second;
                    }
                }

                if (handler)
                {
                    try
                    {
                        handler(num_bytes, overlapped_ptr, ok);
                    }
                    catch (const std::exception& e)
                    {
#ifdef _DEBUG
                        try
                        {
                            OutputDebugStringA(std::format("IOCP handler exception: {}\n", e.what()).c_str());
                        }
                        catch (...)
                        {
                            OutputDebugStringA("IOCP handler exception (format failed)\n");
                        }
#endif
                    }
                    catch (...)
                    {
#ifdef _DEBUG
                        OutputDebugStringA("IOCP handler threw unknown exception\n");
#endif
                    }
                }
                // else: handler was unregistered; ignore
            }
        }

        // ********************************************************************************
        /// <summary>
        /// Signals threads in the thread pool to check for exit.
        /// </summary>
        // ********************************************************************************
        void stop_thread() const noexcept
        {
            OVERLAPPED overlapped{};
            // Post a completion with key == 0 to wake one worker
            // Failure is logged but doesn't throw - shutdown continues best-effort
            if (!PostQueuedCompletionStatus(get(), 0, 0, &overlapped))
            {
#ifdef _DEBUG
                try
                {
                    OutputDebugStringA(std::format("PostQueuedCompletionStatus failed in stop_thread: {}\n", GetLastError()).c_str());
                }
                catch (...)
                {
                    OutputDebugStringA("PostQueuedCompletionStatus failed in stop_thread (format error)\n");
                }
#endif
            }
        }

    public:
        // ********************************************************************************
        /// <summary>
        /// Constructs io_completion_port object from the existing HANDLE.
        /// </summary>
        /// <param name="handle">Existing I/O completion port handle.</param>
        /// <param name="concurrent_threads">Number of concurrent threads
        /// (0 means std::thread::hardware_concurrency()).</param>
        ///
        /// NOTE: Callers should check valid() after construction to ensure handle is valid.
        // ********************************************************************************
        explicit io_completion_port(const HANDLE handle, const size_t concurrent_threads = 0)
            : safe_object_handle(handle)
            , thread_pool(concurrent_threads)
        {
        }

        // ********************************************************************************
        /// <summary>
        /// Constructs a new I/O completion port.
        /// </summary>
        /// <param name="concurrent_threads">Number of concurrent threads for I/O completion port.</param>
        ///
        /// NOTE: Callers MUST check valid() after construction to ensure the IOCP was created successfully.
        ///       If CreateIoCompletionPort fails, the object will be constructed with an invalid handle.
        // ********************************************************************************
        explicit io_completion_port(const size_t concurrent_threads = 0)
            : io_completion_port(
                CreateIoCompletionPort(
                    INVALID_HANDLE_VALUE,
                    nullptr,
                    0,
                    static_cast<DWORD>(concurrent_threads)),
                concurrent_threads)
        {
        }

        // ********************************************************************************
        /// <summary>
        /// Destructor terminates the internal thread pool and cleans up handlers.
        /// </summary>
        // ********************************************************************************
        ~io_completion_port()
        {
            if (active_.load(std::memory_order_acquire))
            {
                try
                {
                    stop_thread_pool();
                }
                catch (const std::exception& e)
                {
                    try
                    {
                        OutputDebugStringA(std::format("~io_completion_port: exception during cleanup: {}\n", e.what()).c_str());
                    }
                    catch (...)
                    {
                        OutputDebugStringA("~io_completion_port: exception during cleanup (format failed)\n");
                    }
                }
                catch (...)
                {
                    OutputDebugStringA("~io_completion_port: unknown exception during cleanup\n");
                }
            }

            // Clear handlers after threads are stopped to prevent resource leaks
            {
                write_lock lock(handlers_lock_);
                handlers_.clear();
            }
        }

        // ********************************************************************************
        /// <summary>
        /// Returns number of concurrent threads for I/O completion port.
        /// </summary>
        // ********************************************************************************
        [[nodiscard]] size_t get_concurrent_threads_num() const noexcept
        {
            return get_concurrent_threads();
        }

        // ********************************************************************************
        /// <summary>
        /// Returns number of worker threads in the internal thread pool.
        /// </summary>
        // ********************************************************************************
        [[nodiscard]] size_t get_working_threads_num() const noexcept
        {
            return get_worker_threads();
        }

        // ********************************************************************************
        /// <summary>
        /// Associates the device with I/O completion port.
        /// </summary>
        /// <param name="file_object">Device file object.</param>
        /// <param name="io_handler">Callback handler for the device-associated I/O.</param>
        /// <returns>Pair of status of the operation and associated I/O completion port key value.</returns>
        ///
        /// THREAD SAFETY:
        /// - This method is thread-safe with respect to other associate/unregister calls.
        /// - Key generation and handler insertion are performed atomically under a single
        ///   write lock to prevent TOCTOU race conditions.
        /// - The handler is stored BEFORE device association to prevent race conditions
        ///   where a completion arrives before the handler is registered.
        /// - If association fails, the handler is automatically cleaned up. This cleanup
        ///   is safe because no I/O completions can be queued for a device that was never
        ///   successfully associated with the IOCP.
        ///
        /// CALLER REQUIREMENTS:
        /// - Do not post overlapped I/O operations on file_object until this method returns
        ///   successfully. Posting I/O before association is undefined behavior.
        /// - The returned key must be used consistently for the lifetime of the association.
        // ********************************************************************************
        [[nodiscard]] std::pair<bool, ULONG_PTR> associate_device(
            const HANDLE file_object,
            const std::function<callback_t>& io_handler)
        {
            // Handler can't be null
            if (!io_handler)
                return { false, 0 };

            // Validate file object
            if (file_object == nullptr || file_object == INVALID_HANDLE_VALUE)
                return { false, 0 };

            ULONG_PTR handler_key = 0;

            // Generate unique key AND insert handler atomically under single write lock.
            // This eliminates the TOCTOU race between key generation and insertion.
            {
                write_lock lock(handlers_lock_);

                constexpr size_t max_attempts = 1000;

                for (size_t attempts = 0; attempts < max_attempts; ++attempts)
                {
                    const ULONG_PTR candidate_key = next_key_.fetch_add(1, std::memory_order_relaxed);

                    // Skip reserved key 0
                    if (candidate_key == 0)
                        continue;

                    // Check for collision and insert atomically
                    if (!handlers_.contains(candidate_key))
                    {
                        handlers_.emplace(candidate_key, io_handler);
                        handler_key = candidate_key;
                        break;
                    }
                }

                if (handler_key == 0)
                {
                    throw std::runtime_error(
                        "io_completion_port: unable to generate unique key after " +
                        std::to_string(max_attempts) + " attempts");
                }
            }

            // Associate the device with the IOCP
            if (const auto h = CreateIoCompletionPort(file_object, get(), handler_key, 0);
                h == get())
            {
                return { true, handler_key };
            }

            // Association failed - cleanup is safe because CreateIoCompletionPort failed,
            // meaning no I/O completions can ever be queued for this handler_key.
            {
                write_lock lock(handlers_lock_);
                handlers_.erase(handler_key);
            }

            return { false, 0 };
        }

        // ********************************************************************************
        /// <summary>
        /// Associates the device with I/O completion port for the existing key
        /// (and thus for the existing stored callback handler).
        /// </summary>
        /// <param name="file_object">Device file object.</param>
        /// <param name="key">I/O completion port key value.</param>
        /// <returns>Boolean status of the operation.</returns>
        // ********************************************************************************
        [[nodiscard]] bool associate_device(const HANDLE file_object, const ULONG_PTR key) const
        {
            // Only associate if we know about this key
            {
                read_lock lock(handlers_lock_);
                if (!handlers_.contains(key))
                    return false;
            }

            if (const auto h = CreateIoCompletionPort(file_object, get(), key, 0);
                h == get())
            {
                return true;
            }

            return false;
        }

        // ********************************************************************************
        /// <summary>
        /// Associates the socket with I/O completion port.
        /// </summary>
        /// <param name="socket">Socket to associate.</param>
        /// <param name="io_handler">Callback handler to process socket I/O operation.</param>
        /// <returns>Pair of status of the operation and associated I/O completion port key value.</returns>
        // ********************************************************************************
        [[nodiscard]] std::pair<bool, ULONG_PTR> associate_socket(
            const SOCKET socket,
            const std::function<callback_t>& io_handler)
        {
            return associate_device(reinterpret_cast<HANDLE>(socket), io_handler); // NOLINT(performance-no-int-to-ptr)
        }

        // ********************************************************************************
        /// <summary>
        /// Associates the socket with I/O completion port with the existing key
        /// (and thus stored callback).
        /// </summary>
        /// <param name="socket">Socket to associate.</param>
        /// <param name="key">I/O completion port key value.</param>
        /// <returns>Boolean status of the operation.</returns>
        // ********************************************************************************
        [[nodiscard]] bool associate_socket(const SOCKET socket, const ULONG_PTR key) const
        {
            return associate_device(reinterpret_cast<HANDLE>(socket), key); // NOLINT(performance-no-int-to-ptr)
        }

        // ********************************************************************************
        /// <summary>
        /// Unregisters a handler associated with the given completion key.
        /// This prevents future IOCP completions from invoking the handler.
        /// In-flight callbacks may still run once if they already copied the handler.
        /// </summary>
        /// <param name="key">I/O completion port key value to unregister.</param>
        /// <returns>true if the handler was found and removed, false otherwise.</returns>
        // ********************************************************************************
        [[nodiscard]] bool unregister_handler(const ULONG_PTR key)
        {
            write_lock lock(handlers_lock_);
            const auto it = handlers_.find(key);
            if (it == handlers_.end())
                return false;

            handlers_.erase(it);
            return true;
        }

        // ********************************************************************************
        /// <summary>
        /// Checks if a handler is currently registered for the given key.
        /// </summary>
        /// <param name="key">I/O completion port key value to check.</param>
        /// <returns>true if the handler is registered and active, false otherwise.</returns>
        // ********************************************************************************
        [[nodiscard]] bool is_handler_registered(const ULONG_PTR key) const
        {
            read_lock lock(handlers_lock_);
            return handlers_.contains(key);
        }
    };
}