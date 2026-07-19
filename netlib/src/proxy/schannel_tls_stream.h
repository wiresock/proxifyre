#pragma once

#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif

#ifndef SCHANNEL_USE_BLACKLISTS
#define SCHANNEL_USE_BLACKLISTS
#endif

#include <WinSock2.h>
#include <security.h>
#include <winternl.h>
#include <schannel.h>
#include <wincrypt.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "socks5_common.h"

namespace proxy
{
    class schannel_tls_stream
    {
    public:
        enum class decrypt_status : uint8_t
        {
            ok,
            need_more_data,
            closed,
            failed
        };

        schannel_tls_stream(const SOCKET socket, socks5_tls_options options)
            : socket_(socket),
              options_(std::move(options)),
              read_buffer_(tls_read_buffer_size)
        {
        }

        schannel_tls_stream(const schannel_tls_stream&) = delete;
        schannel_tls_stream& operator=(const schannel_tls_stream&) = delete;

        schannel_tls_stream(schannel_tls_stream&&) = delete;
        schannel_tls_stream& operator=(schannel_tls_stream&&) = delete;

        ~schannel_tls_stream()
        {
            if (context_acquired_)
            {
                DeleteSecurityContext(&context_);
            }
            if (credentials_acquired_)
            {
                FreeCredentialsHandle(&credentials_);
            }
        }

        [[nodiscard]] const std::string& last_error() const noexcept
        {
            return last_error_;
        }

        [[nodiscard]] bool handshake()
        {
            if (handshake_complete_)
            {
                last_error_ = "SChannel TLS handshake has already completed.";
                return false;
            }

            if (socket_ == INVALID_SOCKET)
            {
                last_error_ = "SChannel TLS socket is invalid.";
                return false;
            }

            if (!options_.pinned_cert_sha256.empty())
            {
                options_.pinned_cert_sha256 = normalize_fingerprint(options_.pinned_cert_sha256);
                if (!is_sha256_fingerprint(options_.pinned_cert_sha256))
                {
                    last_error_ = "SChannel TLS certificate pin must contain exactly 64 hexadecimal digits.";
                    return false;
                }
            }

            if (!options_.allow_invalid_certificate && options_.pinned_cert_sha256.empty() &&
                options_.server_name.empty())
            {
                last_error_ = "SChannel TLS server name is required for certificate validation.";
                return false;
            }

            if (!acquire_credentials())
            {
                return false;
            }

            receive_deadline_guard receive_deadline{ *this };

            constexpr DWORD request_flags =
                ISC_REQ_SEQUENCE_DETECT |
                ISC_REQ_REPLAY_DETECT |
                ISC_REQ_CONFIDENTIALITY |
                ISC_REQ_EXTENDED_ERROR |
                ISC_REQ_ALLOCATE_MEMORY |
                ISC_REQ_STREAM;

            DWORD context_attributes = 0;
            TimeStamp expiry{};
            bool first_call = true;

            while (true)
            {
                SecBuffer out_buffer{};
                out_buffer.BufferType = SECBUFFER_TOKEN;

                SecBufferDesc out_desc{};
                out_desc.ulVersion = SECBUFFER_VERSION;
                out_desc.cBuffers = 1;
                out_desc.pBuffers = &out_buffer;

                SecBuffer in_buffers[2]{};
                SecBufferDesc in_desc{};
                SecBufferDesc* in_desc_ptr = nullptr;

                if (!first_call)
                {
                    if (encrypted_buffer_.empty() && !read_encrypted())
                    {
                        return false;
                    }

                    in_buffers[0].BufferType = SECBUFFER_TOKEN;
                    in_buffers[0].pvBuffer = encrypted_buffer_.data();
                    in_buffers[0].cbBuffer = static_cast<unsigned long>(encrypted_buffer_.size());
                    in_buffers[1].BufferType = SECBUFFER_EMPTY;

                    in_desc.ulVersion = SECBUFFER_VERSION;
                    in_desc.cBuffers = 2;
                    in_desc.pBuffers = in_buffers;
                    in_desc_ptr = &in_desc;
                }

                auto* const context_ptr = context_acquired_ ? &context_ : nullptr;
                const auto status = InitializeSecurityContextA(
                    &credentials_,
                    context_ptr,
                    options_.server_name.empty() ? nullptr : const_cast<SEC_CHAR*>(options_.server_name.c_str()),
                    request_flags,
                    0,
                    SECURITY_NATIVE_DREP,
                    in_desc_ptr,
                    0,
                    &context_,
                    &out_desc,
                    &context_attributes,
                    &expiry);

                if (!context_acquired_ && (status == SEC_I_CONTINUE_NEEDED || status == SEC_E_OK))
                {
                    context_acquired_ = true;
                }

                if (out_buffer.pvBuffer != nullptr)
                {
                    const auto send_result = out_buffer.cbBuffer == 0 ||
                        raw_send_all(out_buffer.pvBuffer, static_cast<int>(out_buffer.cbBuffer));
                    FreeContextBuffer(out_buffer.pvBuffer);
                    if (!send_result)
                    {
                        return false;
                    }
                }

                if (status == SEC_E_INCOMPLETE_MESSAGE)
                {
                    if (!read_encrypted())
                    {
                        return false;
                    }
                    first_call = false;
                    continue;
                }

                if (status == SEC_I_CONTINUE_NEEDED)
                {
                    preserve_extra(in_buffers[1]);
                    first_call = false;
                    continue;
                }

                if (status == SEC_E_OK)
                {
                    preserve_extra(in_buffers[1]);
                    constexpr DWORD required_attributes =
                        ISC_RET_SEQUENCE_DETECT |
                        ISC_RET_REPLAY_DETECT |
                        ISC_RET_CONFIDENTIALITY |
                        ISC_RET_STREAM;
                    if ((context_attributes & required_attributes) != required_attributes)
                    {
                        last_error_ = "SChannel TLS context did not provide the requested stream security attributes.";
                        return false;
                    }

                    const auto stream_status =
                        QueryContextAttributes(&context_, SECPKG_ATTR_STREAM_SIZES, &stream_sizes_);
                    if (stream_status != SEC_E_OK)
                    {
                        set_security_error("SChannel failed to query stream sizes", stream_status);
                        return false;
                    }
                    if (stream_sizes_.cbMaximumMessage == 0)
                    {
                        last_error_ = "SChannel returned an invalid maximum TLS message size.";
                        return false;
                    }

                    if (!verify_peer_certificate())
                    {
                        return false;
                    }

                    handshake_complete_ = true;
                    return true;
                }

                set_security_error("SChannel TLS handshake failed", status);
                return false;
            }
        }

        [[nodiscard]] bool send_all(const void* const data, const int length)
        {
            if (length < 0)
            {
                last_error_ = "SChannel TLS send received an invalid buffer.";
                return false;
            }

            std::vector<char> encrypted;
            if (!encrypt(data, static_cast<size_t>(length), encrypted))
            {
                return false;
            }

            return encrypted.empty() || raw_send_all(encrypted.data(), static_cast<int>(encrypted.size()));
        }

        [[nodiscard]] bool recv_exact(void* const data, const int length)
        {
            if (!handshake_complete_)
            {
                last_error_ = "SChannel TLS receive attempted before handshake completion.";
                return false;
            }
            if (length < 0 || (data == nullptr && length != 0))
            {
                last_error_ = "SChannel TLS receive received an invalid buffer.";
                return false;
            }

            receive_deadline_guard receive_deadline{ *this };

            auto* bytes = static_cast<char*>(data);
            int received = 0;

            while (received < length)
            {
                if (decrypted_buffer_.empty() && !decrypt_next_record())
                {
                    return false;
                }

                const auto to_copy = std::min<int>(
                    length - received,
                    static_cast<int>(decrypted_buffer_.size()));
                memcpy(bytes + received, decrypted_buffer_.data(), to_copy);
                decrypted_buffer_.erase(decrypted_buffer_.begin(), decrypted_buffer_.begin() + to_copy);
                received += to_copy;
            }

            return true;
        }

        /**
         * @brief Encrypts application data into one or more complete TLS records.
         *
         * The returned buffer owns all record bytes and may be used directly by an
         * overlapped WSASend. Calls must be serialized with other encrypt calls for
         * this security context.
         */
        [[nodiscard]] bool encrypt(const void* const data, const size_t length, std::vector<char>& encrypted)
        {
            encrypted.clear();

            if (!handshake_complete_)
            {
                last_error_ = "SChannel TLS encrypt attempted before handshake completion.";
                return false;
            }
            if (data == nullptr && length != 0)
            {
                last_error_ = "SChannel TLS encrypt received an invalid buffer.";
                return false;
            }

            const auto* bytes = static_cast<const char*>(data);
            auto remaining = length;
            while (remaining != 0)
            {
                const auto chunk = static_cast<int>(std::min<size_t>(
                    remaining,
                    static_cast<size_t>(stream_sizes_.cbMaximumMessage)));
                if (!encrypt_chunk(bytes, chunk, encrypted))
                {
                    encrypted.clear();
                    return false;
                }

                bytes += chunk;
                remaining -= static_cast<size_t>(chunk);
            }

            return true;
        }

        /**
         * @brief Adds encrypted bytes and decrypts every complete TLS record currently buffered.
         *
         * SChannel can consume ahead during handshake or a small protocol read. This method
         * therefore also emits plaintext left by recv_exact() and processes encrypted records
         * retained from earlier calls. Incomplete record bytes remain owned by the stream.
         */
        [[nodiscard]] decrypt_status decrypt_available(
            const void* const data,
            const size_t length,
            std::vector<char>& plaintext)
        {
            plaintext.clear();

            if (!handshake_complete_)
            {
                last_error_ = "SChannel TLS decrypt attempted before handshake completion.";
                return decrypt_status::failed;
            }
            if (data == nullptr && length != 0)
            {
                last_error_ = "SChannel TLS decrypt received an invalid buffer.";
                return decrypt_status::failed;
            }

            if (!decrypted_buffer_.empty())
            {
                plaintext = std::move(decrypted_buffer_);
                decrypted_buffer_.clear();
            }

            if (peer_closed_)
            {
                if (length != 0)
                {
                    last_error_ = "SChannel TLS received encrypted data after close_notify.";
                    plaintext.clear();
                    return decrypt_status::failed;
                }
                return decrypt_status::closed;
            }

            if (length != 0)
            {
                const auto* const begin = static_cast<const char*>(data);
                encrypted_buffer_.insert(encrypted_buffer_.end(), begin, begin + length);
            }

            while (!encrypted_buffer_.empty())
            {
                SecBuffer buffers[4]{};
                buffers[0].BufferType = SECBUFFER_DATA;
                buffers[0].pvBuffer = encrypted_buffer_.data();
                buffers[0].cbBuffer = static_cast<unsigned long>(encrypted_buffer_.size());
                buffers[1].BufferType = SECBUFFER_EMPTY;
                buffers[2].BufferType = SECBUFFER_EMPTY;
                buffers[3].BufferType = SECBUFFER_EMPTY;

                SecBufferDesc desc{};
                desc.ulVersion = SECBUFFER_VERSION;
                desc.cBuffers = 4;
                desc.pBuffers = buffers;

                const auto status = DecryptMessage(&context_, &desc, 0, nullptr);
                if (status == SEC_E_INCOMPLETE_MESSAGE)
                {
                    return plaintext.empty() ? decrypt_status::need_more_data : decrypt_status::ok;
                }
                if (status == SEC_I_CONTEXT_EXPIRED)
                {
                    encrypted_buffer_.clear();
                    peer_closed_ = true;
                    last_error_ = "SChannel TLS stream closed.";
                    return decrypt_status::closed;
                }
                if (status != SEC_E_OK)
                {
                    set_security_error(
                        status == SEC_I_RENEGOTIATE
                            ? "SChannel TLS renegotiation is not supported"
                            : "SChannel failed to decrypt data",
                        status);
                    plaintext.clear();
                    return decrypt_status::failed;
                }

                std::vector<char> extra;
                for (const auto& buffer : buffers)
                {
                    if (buffer.BufferType == SECBUFFER_DATA && buffer.pvBuffer != nullptr && buffer.cbBuffer != 0)
                    {
                        const auto* const begin = static_cast<const char*>(buffer.pvBuffer);
                        plaintext.insert(plaintext.end(), begin, begin + buffer.cbBuffer);
                    }
                    else if (buffer.BufferType == SECBUFFER_EXTRA && buffer.pvBuffer != nullptr && buffer.cbBuffer != 0)
                    {
                        const auto* const begin = static_cast<const char*>(buffer.pvBuffer);
                        extra.assign(begin, begin + buffer.cbBuffer);
                    }
                }

                encrypted_buffer_ = std::move(extra);
            }

            return plaintext.empty() ? decrypt_status::need_more_data : decrypt_status::ok;
        }

        /**
         * @brief Creates the TLS close_notify token for an orderly client shutdown.
         */
        [[nodiscard]] bool create_shutdown_token(std::vector<char>& token)
        {
            token.clear();
            if (!handshake_complete_ || !context_acquired_)
            {
                last_error_ = "SChannel TLS shutdown attempted before handshake completion.";
                return false;
            }
            if (shutdown_started_)
            {
                last_error_ = "SChannel TLS shutdown has already started.";
                return false;
            }

            DWORD shutdown_control = SCHANNEL_SHUTDOWN;
            SecBuffer control_buffer{};
            control_buffer.BufferType = SECBUFFER_TOKEN;
            control_buffer.pvBuffer = &shutdown_control;
            control_buffer.cbBuffer = sizeof(shutdown_control);

            SecBufferDesc control_desc{};
            control_desc.ulVersion = SECBUFFER_VERSION;
            control_desc.cBuffers = 1;
            control_desc.pBuffers = &control_buffer;

            auto status = ApplyControlToken(&context_, &control_desc);
            if (status != SEC_E_OK)
            {
                set_security_error("SChannel failed to apply the TLS shutdown token", status);
                return false;
            }

            shutdown_started_ = true;

            SecBuffer out_buffer{};
            out_buffer.BufferType = SECBUFFER_TOKEN;
            SecBufferDesc out_desc{};
            out_desc.ulVersion = SECBUFFER_VERSION;
            out_desc.cBuffers = 1;
            out_desc.pBuffers = &out_buffer;

            constexpr DWORD request_flags =
                ISC_REQ_SEQUENCE_DETECT |
                ISC_REQ_REPLAY_DETECT |
                ISC_REQ_CONFIDENTIALITY |
                ISC_REQ_EXTENDED_ERROR |
                ISC_REQ_ALLOCATE_MEMORY |
                ISC_REQ_STREAM;
            DWORD context_attributes = 0;
            TimeStamp expiry{};
            status = InitializeSecurityContextA(
                &credentials_,
                &context_,
                options_.server_name.empty() ? nullptr : const_cast<SEC_CHAR*>(options_.server_name.c_str()),
                request_flags,
                0,
                SECURITY_NATIVE_DREP,
                nullptr,
                0,
                &context_,
                &out_desc,
                &context_attributes,
                &expiry);

            const auto shutdown_status_ok = status == SEC_E_OK ||
                status == SEC_I_CONTEXT_EXPIRED ||
                status == SEC_I_CONTINUE_NEEDED;
            if (out_buffer.pvBuffer != nullptr && out_buffer.cbBuffer != 0)
            {
                const auto* const begin = static_cast<const char*>(out_buffer.pvBuffer);
                token.assign(begin, begin + out_buffer.cbBuffer);
            }
            if (out_buffer.pvBuffer != nullptr)
            {
                FreeContextBuffer(out_buffer.pvBuffer);
            }

            if (!shutdown_status_ok)
            {
                set_security_error("SChannel failed to create the TLS shutdown token", status);
                token.clear();
                return false;
            }
            if (token.empty())
            {
                last_error_ = "SChannel returned an empty TLS shutdown token.";
                return false;
            }

            return true;
        }

    private:
        class receive_deadline_guard
        {
        public:
            explicit receive_deadline_guard(schannel_tls_stream& stream) noexcept
                : stream_(stream)
            {
                int timeout_size = static_cast<int>(sizeof(original_timeout_));
                if (getsockopt(stream_.socket_, SOL_SOCKET, SO_RCVTIMEO,
                    reinterpret_cast<char*>(&original_timeout_), &timeout_size) == SOCKET_ERROR)
                {
                    original_timeout_ = receive_operation_timeout_ms;
                }

                stream_.receive_deadline_ = GetTickCount64() + receive_operation_timeout_ms;
                stream_.receive_deadline_active_ = true;
            }

            receive_deadline_guard(const receive_deadline_guard&) = delete;
            receive_deadline_guard& operator=(const receive_deadline_guard&) = delete;

            ~receive_deadline_guard()
            {
                stream_.receive_deadline_active_ = false;
                setsockopt(stream_.socket_, SOL_SOCKET, SO_RCVTIMEO,
                    reinterpret_cast<const char*>(&original_timeout_), sizeof(original_timeout_));
            }

        private:
            schannel_tls_stream& stream_;
            DWORD original_timeout_ = receive_operation_timeout_ms;
        };

        [[nodiscard]] bool acquire_credentials()
        {
            DWORD credential_flags = SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO;
            if (options_.allow_invalid_certificate || !options_.pinned_cert_sha256.empty())
            {
                credential_flags |= SCH_CRED_MANUAL_CRED_VALIDATION;
            }
            else
            {
                credential_flags |=
                    SCH_CRED_AUTO_CRED_VALIDATION |
                    SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT |
                    SCH_CRED_IGNORE_NO_REVOCATION_CHECK |
                    SCH_CRED_IGNORE_REVOCATION_OFFLINE;
            }

            // Keep the record layer on TLS 1.2. SChannel exposes TLS 1.3
            // post-handshake messages through SEC_I_RENEGOTIATE, which requires a second
            // asynchronous handshake state machine during relay. Alighieri enables its
            // rustls TLS 1.2 provider, so this remains interoperable without accepting
            // obsolete protocol versions.
            TLS_PARAMETERS tls_parameters{};
            tls_parameters.grbitDisabledProtocols =
                SP_PROT_SSL2_CLIENT |
                SP_PROT_SSL3_CLIENT |
                SP_PROT_TLS1_0_CLIENT |
                SP_PROT_TLS1_1_CLIENT |
                SP_PROT_TLS1_3_CLIENT;

            SCH_CREDENTIALS credentials{};
            credentials.dwVersion = SCH_CREDENTIALS_VERSION;
            credentials.dwFlags = credential_flags;
            credentials.cTlsParameters = 1;
            credentials.pTlsParameters = &tls_parameters;

            TimeStamp expiry{};
            auto status = AcquireCredentialsHandleA(
                nullptr,
                const_cast<SEC_CHAR*>(UNISP_NAME_A),
                SECPKG_CRED_OUTBOUND,
                nullptr,
                &credentials,
                nullptr,
                nullptr,
                &credentials_,
                &expiry);

            // SCH_CREDENTIALS was added for crypto-agile TLS configuration. Fall back to
            // SCHANNEL_CRED on older Windows releases that do not recognize version 5.
            if (status != SEC_E_OK)
            {
                SCHANNEL_CRED legacy_credentials{};
                legacy_credentials.dwVersion = SCHANNEL_CRED_VERSION;
                legacy_credentials.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
                legacy_credentials.dwFlags = credential_flags;
                status = AcquireCredentialsHandleA(
                    nullptr,
                    const_cast<SEC_CHAR*>(UNISP_NAME_A),
                    SECPKG_CRED_OUTBOUND,
                    nullptr,
                    &legacy_credentials,
                    nullptr,
                    nullptr,
                    &credentials_,
                    &expiry);
            }

            if (status != SEC_E_OK)
            {
                set_security_error("SChannel failed to acquire credentials", status);
                return false;
            }

            credentials_acquired_ = true;
            return true;
        }

        [[nodiscard]] bool encrypt_chunk(
            const char* const data,
            const int length,
            std::vector<char>& encrypted)
        {
            std::vector<char> packet(
                stream_sizes_.cbHeader + length + stream_sizes_.cbTrailer);
            memcpy(packet.data() + stream_sizes_.cbHeader, data, length);

            SecBuffer buffers[4]{};
            buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
            buffers[0].pvBuffer = packet.data();
            buffers[0].cbBuffer = stream_sizes_.cbHeader;
            buffers[1].BufferType = SECBUFFER_DATA;
            buffers[1].pvBuffer = packet.data() + stream_sizes_.cbHeader;
            buffers[1].cbBuffer = static_cast<unsigned long>(length);
            buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
            buffers[2].pvBuffer = packet.data() + stream_sizes_.cbHeader + length;
            buffers[2].cbBuffer = stream_sizes_.cbTrailer;
            buffers[3].BufferType = SECBUFFER_EMPTY;

            SecBufferDesc desc{};
            desc.ulVersion = SECBUFFER_VERSION;
            desc.cBuffers = 4;
            desc.pBuffers = buffers;

            const auto status = EncryptMessage(&context_, 0, &desc, 0);
            if (status != SEC_E_OK)
            {
                set_security_error("SChannel failed to encrypt data", status);
                return false;
            }

            const auto packet_size = buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer;
            encrypted.insert(encrypted.end(), packet.data(), packet.data() + packet_size);
            return true;
        }

        [[nodiscard]] bool decrypt_next_record()
        {
            while (true)
            {
                std::vector<char> plaintext;
                const auto status = decrypt_available(nullptr, 0, plaintext);
                if (status == decrypt_status::failed)
                {
                    return false;
                }
                if (!plaintext.empty())
                {
                    decrypted_buffer_ = std::move(plaintext);
                    return true;
                }
                if (status == decrypt_status::closed)
                {
                    return false;
                }
                if (!read_encrypted())
                {
                    return false;
                }
            }
        }

        [[nodiscard]] bool read_encrypted()
        {
            if (receive_deadline_active_)
            {
                const auto now = GetTickCount64();
                if (now >= receive_deadline_)
                {
                    last_error_ = "SChannel TLS receive operation timed out.";
                    return false;
                }

                auto remaining_ms = static_cast<DWORD>(receive_deadline_ - now);
                if (setsockopt(socket_, SOL_SOCKET, SO_RCVTIMEO,
                    reinterpret_cast<const char*>(&remaining_ms), sizeof(remaining_ms)) == SOCKET_ERROR)
                {
                    last_error_ = "SChannel failed to set the TLS receive timeout: " +
                        std::to_string(WSAGetLastError());
                    return false;
                }
            }

            const auto received = recv(socket_, read_buffer_.data(), static_cast<int>(read_buffer_.size()), 0);
            if (received == SOCKET_ERROR)
            {
                last_error_ = "SChannel TLS socket recv failed: " + std::to_string(WSAGetLastError());
                return false;
            }
            if (received == 0)
            {
                last_error_ = "SChannel TLS socket closed by peer.";
                return false;
            }

            encrypted_buffer_.insert(encrypted_buffer_.end(), read_buffer_.data(), read_buffer_.data() + received);
            return true;
        }

        [[nodiscard]] bool raw_send_all(const void* const data, const int length)
        {
            auto* bytes = static_cast<const char*>(data);
            int sent_total = 0;
            while (sent_total < length)
            {
                const auto sent = send(socket_, bytes + sent_total, length - sent_total, 0);
                if (sent == SOCKET_ERROR)
                {
                    last_error_ = "SChannel TLS socket send failed: " + std::to_string(WSAGetLastError());
                    return false;
                }
                if (sent == 0)
                {
                    last_error_ = "SChannel TLS socket send returned zero bytes.";
                    return false;
                }
                sent_total += sent;
            }

            return true;
        }

        void preserve_extra(const SecBuffer& buffer)
        {
            if (buffer.BufferType == SECBUFFER_EXTRA && buffer.pvBuffer != nullptr && buffer.cbBuffer != 0)
            {
                const auto* begin = static_cast<const char*>(buffer.pvBuffer);
                std::vector<char> extra(begin, begin + buffer.cbBuffer);
                encrypted_buffer_ = std::move(extra);
            }
            else
            {
                encrypted_buffer_.clear();
            }
        }

        [[nodiscard]] bool verify_peer_certificate()
        {
            if (options_.pinned_cert_sha256.empty())
            {
                return true;
            }

            PCCERT_CONTEXT cert = nullptr;
            const auto status = QueryContextAttributes(&context_, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &cert);
            if (status != SEC_E_OK)
            {
                set_security_error("SChannel failed to query peer certificate", status);
                return false;
            }
            if (cert == nullptr)
            {
                last_error_ = "SChannel returned no peer certificate.";
                return false;
            }

            std::array<BYTE, 32> hash{};
            DWORD hash_size = static_cast<DWORD>(hash.size());
            const auto hash_result = CryptHashCertificate(
                0,
                CALG_SHA_256,
                0,
                cert->pbCertEncoded,
                cert->cbCertEncoded,
                hash.data(),
                &hash_size);
            const auto hash_error = hash_result ? ERROR_SUCCESS : GetLastError();
            CertFreeCertificateContext(cert);

            if (!hash_result)
            {
                last_error_ = "SChannel failed to hash peer certificate: " + std::to_string(hash_error);
                return false;
            }
            if (hash_size != hash.size())
            {
                last_error_ = "SChannel returned an invalid SHA-256 certificate hash size.";
                return false;
            }

            if (hex_encode(hash.data(), hash_size) != options_.pinned_cert_sha256)
            {
                last_error_ = "SChannel peer certificate SHA-256 fingerprint did not match the configured pin.";
                return false;
            }

            return true;
        }

        static std::string normalize_fingerprint(const std::string& value)
        {
            std::string normalized;
            normalized.reserve(value.size());
            for (const auto ch : value)
            {
                if (ch == ':' || ch == '-' || std::isspace(static_cast<unsigned char>(ch)))
                {
                    continue;
                }
                normalized.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
            }
            return normalized;
        }

        static bool is_sha256_fingerprint(const std::string& value)
        {
            return value.size() == 64 && std::all_of(value.begin(), value.end(), [](const unsigned char ch)
            {
                return std::isxdigit(ch) != 0;
            });
        }

        static std::string hex_encode(const BYTE* const data, const DWORD length)
        {
            std::ostringstream stream;
            stream << std::hex << std::setfill('0');
            for (DWORD i = 0; i < length; ++i)
            {
                stream << std::setw(2) << static_cast<unsigned int>(data[i]);
            }
            return stream.str();
        }

        void set_security_error(const std::string& prefix, const SECURITY_STATUS status)
        {
            std::ostringstream stream;
            stream << prefix << ": 0x" << std::hex << static_cast<unsigned long>(status);
            last_error_ = stream.str();
        }

        SOCKET socket_{ INVALID_SOCKET };
        socks5_tls_options options_;
        CredHandle credentials_{};
        CtxtHandle context_{};
        SecPkgContext_StreamSizes stream_sizes_{};
        bool credentials_acquired_ = false;
        bool context_acquired_ = false;
        bool handshake_complete_ = false;
        bool peer_closed_ = false;
        bool shutdown_started_ = false;
        bool receive_deadline_active_ = false;
        ULONGLONG receive_deadline_ = 0;
        static constexpr DWORD receive_operation_timeout_ms = 5000;
        static constexpr auto tls_read_buffer_size = 16 * 1024;
        std::vector<char> read_buffer_;
        std::vector<char> encrypted_buffer_;
        std::vector<char> decrypted_buffer_;
        std::string last_error_;
    };
}
