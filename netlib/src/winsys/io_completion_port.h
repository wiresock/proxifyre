#pragma once

namespace winsys
{
	// --------------------------------------------------------------------------------
	/// <summary>
	/// represents a thread pool for the derived CRTP classes
	/// \tparam T CRTP derived class should provide start_thread and stop_thread routines
	/// </summary>
	// --------------------------------------------------------------------------------
	template <typename T>
	class thread_pool
	{
		/// <summary>working threads container</summary>
		std::vector<std::thread> threads_;

	protected:
		/// <summary>thread pool termination flag</summary>
		std::atomic_bool active_{false};
		/// <summary>number of concurrent threads in the pool</summary>
		uint32_t concurrent_threads_;

	public:
		thread_pool(const thread_pool& other) = delete;

		thread_pool(thread_pool&& other) noexcept
			: threads_(std::move(other.threads_)),
			  active_(other.active_.load()),
			  concurrent_threads_(other.concurrent_threads_)
		{
		}

		thread_pool& operator=(const thread_pool& other) = delete;

		thread_pool& operator=(thread_pool&& other) noexcept
		{
			if (this == &other)
				return *this;
			threads_ = std::move(other.threads_);
			active_ = other.active_.load();
			concurrent_threads_ = other.concurrent_threads_;
			return *this;
		}

		~thread_pool() = default;

		// ********************************************************************************
		/// <summary>
		/// initializes thread_pool with specified number of concurrent threads
		/// </summary>
		/// <param name="concurrent_threads">number of concurrent threads in the pool</param>
		/// <returns></returns>
		// ********************************************************************************
		explicit thread_pool(const uint32_t concurrent_threads = 0) noexcept:
			concurrent_threads_{(concurrent_threads == 0) ? std::thread::hardware_concurrency() : concurrent_threads}
		{
		}

		// ********************************************************************************
		/// <summary>
		/// starts threads in the pool if not already started
		/// </summary>
		// ********************************************************************************
		void start_thread_pool()
		{
			if (active_ == true)
				return;

			active_ = true;

			// Create twice as many threads as may run concurrently
			for (size_t i = 0; i < concurrent_threads_ * 2; ++i)
			{
				threads_.push_back(std::thread(&T::start_thread, static_cast<T*>(this)));
			}
		}

		// ********************************************************************************
		/// <summary>
		/// stops threads in the pool using CRTP derived class stop_thread method
		/// </summary>
		// ********************************************************************************
		void stop_thread_pool()
		{
			if (active_ == false)
				return;

			active_ = false;

			for (size_t i = 0; i < threads_.size(); ++i)
			{
				static_cast<T&>(*this).stop_thread();
			}

			for (auto&& thread : threads_)
			{
				if (thread.joinable())
					thread.join();
			}
		}
	};

	// --------------------------------------------------------------------------------
	/// <summary>
	/// Windows I/O completion port wrapper with internal thread pool
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
		/// type of completion key callback
		/// </summary>
		/// <param name="DWORD"></param>
		/// <param name="OVERLAPPED*"></param>
		/// <returns>boolean status of operation</returns>
		// ********************************************************************************
		using callback_t = bool(DWORD, OVERLAPPED*, BOOL);

		io_completion_port(const io_completion_port& other) = delete;

		io_completion_port(io_completion_port&& other) noexcept // NOLINT(bugprone-exception-escape)
			: safe_object_handle(std::move(static_cast<safe_object_handle&>(other))),
			  thread_pool<io_completion_port>(std::move(static_cast<thread_pool<io_completion_port>&>(other)))

		{
			write_lock rhs_lk(other.handlers_lock_);
			handlers_ = std::move(other.handlers_);
			handlers_keys_ = std::move(other.handlers_keys_);
		}

		io_completion_port& operator=(const io_completion_port& other) = delete;

		io_completion_port& operator=(io_completion_port&& other) noexcept // NOLINT(bugprone-exception-escape)
		{
			if (this == &other)
				return *this;

			write_lock lhs_lk(handlers_lock_, std::defer_lock);
			write_lock rhs_lk(other.handlers_lock_, std::defer_lock);
			std::lock(lhs_lk, rhs_lk);

			safe_object_handle::operator =(std::move(static_cast<safe_object_handle&>(other)));
			thread_pool<io_completion_port>::operator
				=(std::move(static_cast<thread_pool<io_completion_port>&>(other)));
			handlers_ = std::move(other.handlers_);
			handlers_keys_ = std::move(other.handlers_keys_);
			return *this;
		}

	private:
		/// <summary>synchronization lock for handlers below (accessed concurrently)</summary>
		mutex_type handlers_lock_;
		/// <summary>callback handlers storage</summary>
		std::vector<std::unique_ptr<std::function<callback_t>>> handlers_;
		/// <summary>callback keys (convertible to pointers in the storage above)</summary>
		std::set<ULONG_PTR> handlers_keys_;

		// ********************************************************************************
		/// <summary>
		/// working thread routine (calls stored functions by the I/O completion key)
		/// </summary>
		// ********************************************************************************
		void start_thread() const
		{
			DWORD num_bytes;
			ULONG_PTR completion_key;
			OVERLAPPED* overlapped_ptr;

			do
			{
				const auto ok =
					GetQueuedCompletionStatus(get(), &num_bytes, &completion_key, &overlapped_ptr, INFINITE);

				if (!active_)
					return;

				if (completion_key)
				{
					if (const auto* const handler = reinterpret_cast<std::function<callback_t>*>(completion_key); *handler) // NOLINT(performance-no-int-to-ptr)
					{
						(*handler)(num_bytes, overlapped_ptr, ok);
					}
				}
			}
			while (active_);
		}

		// ********************************************************************************
		/// <summary>
		/// signals threads in the thread pool to check for exit
		/// </summary>
		// ********************************************************************************
		void stop_thread() const noexcept
		{
			OVERLAPPED overlapped{};
			PostQueuedCompletionStatus(get(), 0, 0, &overlapped);
		}

	public:
		// ********************************************************************************
		/// <summary>
		/// constructs io_completion_port object from the existing HANDLE
		/// </summary>
		/// <param name="handle">existing I/O completion port handle</param>
		/// <param name="concurrent_threads">number of concurrent threads for I/O completion port (zero means as many threads as cores)</param>
		/// <returns></returns>
		// ********************************************************************************
		explicit io_completion_port(HANDLE handle, const uint32_t concurrent_threads = 0) :
			safe_object_handle(handle),
			thread_pool<io_completion_port>(concurrent_threads)
		{
		}

		// ********************************************************************************
		/// <summary>
		/// constructs a new I/O completion port
		/// </summary>
		/// <param name="concurrent_threads">number of concurrent threads for I/O completion port</param>
		/// <returns></returns>
		// ********************************************************************************
		explicit io_completion_port(const uint32_t concurrent_threads = 0):
			io_completion_port(
				CreateIoCompletionPort(
					INVALID_HANDLE_VALUE,
					nullptr,
					0,
					static_cast<DWORD>(concurrent_threads)),
				concurrent_threads
			)
		{
		}

		// ********************************************************************************
		/// <summary>
		/// destructor terminates the internal thread pool
		/// </summary>
		/// <returns></returns>
		// ********************************************************************************
		~io_completion_port()
		{
			if (active_ == false)
				return;

			try
			{
				stop_thread_pool();
			}
			catch (...)
			{
			}
		}

		// ********************************************************************************
		/// <summary>
		/// returns number of concurrent threads for I/O completion port
		/// </summary>
		/// <returns>number of concurrent threads for I/O completion port</returns>
		// ********************************************************************************
		uint32_t get_concurrent_threads_num() const noexcept { return concurrent_threads_; }

		// ********************************************************************************
		/// <summary>
		/// returns number of concurrent threads in the internal thread pool
		/// </summary>
		/// <returns>number of concurrent threads in the internal thread pool</returns>
		// ********************************************************************************
		uint32_t get_working_threads_num() const noexcept { return concurrent_threads_ * 2; }

		// ********************************************************************************
		/// <summary>
		/// associates the device with I/O completion port
		/// </summary>
		/// <param name="file_object">device file object</param>
		/// <param name="io_handler">callback handler for the device associated I/O</param>
		/// <returns>pair of status of the operation and associated I/O completion port key value</returns>
		// ********************************************************************************
		std::pair<bool, ULONG_PTR> associate_device(HANDLE file_object, const std::function<callback_t>& io_handler)
		{
			// handler can't be null
			if (!io_handler)
				return std::make_pair(false, 0);

			// Create storage for the callback and use pointer to that storage as an I/O completion port key
			auto handler_ptr = std::make_unique<std::function<callback_t>>(io_handler);
			auto handler_key = reinterpret_cast<ULONG_PTR>(handler_ptr.get());

			const auto h = CreateIoCompletionPort(file_object, get(), handler_key, 0);

			if (h == get())
			{
				{
					// Store the key and pointer for the handler
					std::lock_guard lock(handlers_lock_);
					handlers_keys_.insert(handler_key);
					handlers_.push_back(std::move(handler_ptr));
				}

				return std::make_pair(true, handler_key);
			}
			return std::make_pair(false, 0);
		}

		// ********************************************************************************
		/// <summary>
		/// associates the device with I/O completion port for the existing key (and thus for the existing stored callback handler)
		/// </summary>
		/// <param name="file_object">device file object</param>
		/// <param name="key">I/O completion port key value</param>
		/// <returns>boolean status of the operation</returns>
		// ********************************************************************************
		bool associate_device(HANDLE file_object, const ULONG_PTR key)
		{
			std::shared_lock lock(handlers_lock_);

			if (const auto it = handlers_keys_.find(key); it != handlers_keys_.end())
			{
				if (const auto h = CreateIoCompletionPort(file_object, get(), key, 0); h == get())
				{
					return true;
				}
			}

			return false;
		}

		// ********************************************************************************
		/// <summary>
		/// associates the socket with I/O completion port
		/// </summary>
		/// <param name="socket">socket to associate</param>
		/// <param name="io_handler">callback handler to process socket I/O operation</param>
		/// <returns>pair of status of the operation and associated I/O completion port key value</returns>
		// ********************************************************************************
		std::pair<bool, ULONG_PTR> associate_socket(const SOCKET socket, const std::function<callback_t>& io_handler)
		{
			return associate_device(reinterpret_cast<HANDLE>(socket), io_handler); // NOLINT(performance-no-int-to-ptr)
		}

		// ********************************************************************************
		/// <summary>
		/// associates the socket with I/O completion port with the existing key (and thus stored callback)
		/// </summary>
		/// <param name="socket">socket to associate</param>
		/// <param name="key">key I/O completion port key value</param>
		/// <returns>boolean status of the operation</returns>
		// ********************************************************************************
		bool associate_socket(const SOCKET socket, const ULONG_PTR key)
		{
			return associate_device(reinterpret_cast<HANDLE>(socket), key); // NOLINT(performance-no-int-to-ptr)
		}
	};
}
