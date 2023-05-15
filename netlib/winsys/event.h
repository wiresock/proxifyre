#pragma once

#pragma warning( push )
#pragma warning( disable : 26456 )

namespace winsys
{
	// --------------------------------------------------------------------------------
	/// <summary>
	/// Simple wrapper for Windows event object
	/// </summary>
	// --------------------------------------------------------------------------------
	class safe_event final : public safe_object_handle
	{
	public:
		/// <summary>
		/// Constructs safe_event from the even object handle
		/// </summary>
		// ReSharper disable once CppParameterMayBeConst
		explicit safe_event(HANDLE handle = nullptr) noexcept: safe_object_handle(handle)
		{
		}

		/// <summary>
		/// Deleted copy constructor
		/// </summary>
		safe_event(const safe_event& other) = delete;

		/// <summary>
		/// Move constructor
		/// </summary>
		/// <param name="other">Object instance to move from</param>
		safe_event(safe_event&& other) noexcept
			: safe_object_handle{std::move(other)}
		{
		}

		/// <summary>
		/// Deleted copy assignment
		/// </summary>
		safe_event& operator=(const safe_event& other) = delete;

		/// <summary>
		/// Move assignment
		/// </summary>
		/// <param name="other">Object instance to move from</param>
		/// <returns>this object instance</returns>
		safe_event& operator=(safe_event&& other) noexcept
		{
			if (this == &other)
				return *this;
			safe_object_handle::operator =(std::move(other));
			return *this;
		}

		/// <summary>
		/// Default destructor 
		/// </summary>
		~safe_event() = default;

		/// <summary>
		/// Waits on the event 
		/// </summary>
		/// <param name="dw_milliseconds">Wait timeout in milliseconds</param>
		/// <returns>value returned by WaitForSingleObject</returns>
		[[nodiscard]] unsigned wait(const unsigned dw_milliseconds) const noexcept
		{
			return WaitForSingleObject(get(), dw_milliseconds);
		}

		/// <summary>
		/// Signals the event object
		/// </summary>
		/// <returns>true if the function succeeds, false otherwise</returns>
		[[nodiscard]] bool signal() const noexcept
		{
			return SetEvent(get()) ? true : false;
		}

		/// <summary>
		/// Resets event
		/// </summary>
		/// <returns>true if the function succeeds, false otherwise</returns>
		[[nodiscard]] bool reset_event() const noexcept
		{
			return ResetEvent(get()) ? true : false;
		}
	};
}
#pragma warning( pop )
