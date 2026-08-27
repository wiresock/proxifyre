using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;

namespace ProxiFyreUI.Infrastructure
{
    /// <summary>
    /// Coordinates one UI process for each Windows identity and terminal session without opening
    /// a remoting or network endpoint.
    /// </summary>
    internal sealed class SingleInstanceCoordinator : IDisposable
    {
        private const string ApplicationId = "7790e7d3-66f9-4e93-a9db-967ddcecc76d";
        private static readonly object ProcessPrimaryGate = new object();
        private static readonly HashSet<string> ProcessPrimaryNames =
            new HashSet<string>(StringComparer.Ordinal);
        private readonly object _gate = new object();
        private readonly Mutex _instanceMutex;
        private readonly string _instanceMutexName;
        private readonly EventWaitHandle _activationEvent;
        private readonly RegisteredWaitHandle _activationWait;
        private Action _activationCallback;
        private bool _activationPending;
        private bool _disposed;

        private SingleInstanceCoordinator(Mutex instanceMutex, string instanceMutexName,
            EventWaitHandle activationEvent, bool isPrimary)
        {
            _instanceMutex = instanceMutex;
            _instanceMutexName = instanceMutexName;
            _activationEvent = activationEvent;
            IsPrimary = isPrimary;
            if (isPrimary)
                _activationWait = ThreadPool.RegisterWaitForSingleObject(
                    activationEvent, ActivationSignaled, null, Timeout.Infinite, false);
        }

        public bool IsPrimary { get; }

        public static SingleInstanceCoordinator CreateForCurrentUser()
        {
            using (var identity = WindowsIdentity.GetCurrent())
            {
                var user = identity.User;
                if (user == null)
                    throw new InvalidOperationException(
                        "The current Windows identity has no security identifier.");
                return Create(BuildObjectNamePrefix(user,
                    Process.GetCurrentProcess().SessionId), user);
            }
        }

        internal static SingleInstanceCoordinator Create(string objectNamePrefix)
        {
            using (var identity = WindowsIdentity.GetCurrent())
            {
                var user = identity.User;
                if (user == null)
                    throw new InvalidOperationException(
                        "The current Windows identity has no security identifier.");
                return Create(objectNamePrefix, user);
            }
        }

        internal static string BuildObjectNamePrefix(SecurityIdentifier user, int sessionId)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (sessionId < 0)
                throw new ArgumentOutOfRangeException(nameof(sessionId));
            return string.Format(
                @"Local\ProxiFyreUI.{0}.{1}.Session-{2}",
                ApplicationId, user.Value, sessionId);
        }

        public void RequestActivation()
        {
            if (IsPrimary)
                throw new InvalidOperationException(
                    "The primary instance cannot request activation from itself.");
            lock (_gate)
            {
                ThrowIfDisposed();
                _activationEvent.Set();
            }
        }

        public void SetActivationCallback(Action callback)
        {
            if (!IsPrimary)
                throw new InvalidOperationException(
                    "Only the primary instance can receive activation requests.");
            if (callback == null)
                throw new ArgumentNullException(nameof(callback));

            Action pendingCallback = null;
            lock (_gate)
            {
                ThrowIfDisposed();
                _activationCallback = callback;
                if (_activationPending)
                {
                    _activationPending = false;
                    pendingCallback = callback;
                }
            }

            InvokeActivationCallback(pendingCallback);
        }

        private static SingleInstanceCoordinator Create(string objectNamePrefix,
            SecurityIdentifier user)
        {
            if (string.IsNullOrWhiteSpace(objectNamePrefix))
                throw new ArgumentException("An object-name prefix is required.",
                    nameof(objectNamePrefix));

            var eventSecurity = new EventWaitHandleSecurity();
            eventSecurity.SetAccessRuleProtection(true, false);
            eventSecurity.AddAccessRule(new EventWaitHandleAccessRule(user,
                EventWaitHandleRights.FullControl, AccessControlType.Allow));

            bool eventCreated;
            var activationEvent = new EventWaitHandle(false, EventResetMode.AutoReset,
                objectNamePrefix + ".Activation", out eventCreated, eventSecurity);
            try
            {
                var mutexSecurity = new MutexSecurity();
                mutexSecurity.SetAccessRuleProtection(true, false);
                mutexSecurity.AddAccessRule(new MutexAccessRule(user, MutexRights.FullControl,
                    AccessControlType.Allow));

                var mutexName = objectNamePrefix + ".Instance";
                bool mutexCreated;
                var mutex = new Mutex(false, mutexName, out mutexCreated, mutexSecurity);
                var ownsMutex = false;
                try
                {
                    ownsMutex = TryAcquirePrimaryMutex(mutex, mutexName);
                    return new SingleInstanceCoordinator(mutex, mutexName, activationEvent,
                        ownsMutex);
                }
                catch
                {
                    if (ownsMutex)
                        ReleasePrimaryMutex(mutex, mutexName);
                    mutex.Dispose();
                    throw;
                }
            }
            catch
            {
                activationEvent.Dispose();
                throw;
            }
        }

        private static bool TryAcquirePrimaryMutex(Mutex mutex, string mutexName)
        {
            lock (ProcessPrimaryGate)
            {
                // Windows mutex acquisition is recursive for the owning thread. Track the
                // process claim separately so a second coordinator in this process is still a
                // secondary instance instead of recursively acquiring the same mutex.
                if (ProcessPrimaryNames.Contains(mutexName))
                    return false;

                bool acquired;
                try
                {
                    acquired = mutex.WaitOne(0, false);
                }
                catch (AbandonedMutexException)
                {
                    // The former primary terminated without releasing ownership. Windows grants
                    // ownership to this thread while reporting the abandonment.
                    acquired = true;
                }

                if (acquired)
                    ProcessPrimaryNames.Add(mutexName);
                return acquired;
            }
        }

        private static void ReleasePrimaryMutex(Mutex mutex, string mutexName)
        {
            lock (ProcessPrimaryGate)
            {
                try
                {
                    mutex.ReleaseMutex();
                }
                finally
                {
                    ProcessPrimaryNames.Remove(mutexName);
                }
            }
        }

        private void ActivationSignaled(object state, bool timedOut)
        {
            if (timedOut)
                return;

            Action callback;
            lock (_gate)
            {
                if (_disposed)
                    return;
                callback = _activationCallback;
                if (callback == null)
                {
                    _activationPending = true;
                    return;
                }
            }

            InvokeActivationCallback(callback);
        }

        private static void InvokeActivationCallback(Action callback)
        {
            if (callback == null)
                return;
            try
            {
                callback();
            }
            catch
            {
                // An activation request is advisory and must never terminate the primary UI.
            }
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(SingleInstanceCoordinator));
        }

        public void Dispose()
        {
            lock (_gate)
            {
                if (_disposed)
                    return;
                _disposed = true;
                _activationCallback = null;
            }

            // Stop advertising this process as the primary before dismantling its activation
            // endpoint. A launch racing with shutdown can acquire the existing mutex even when
            // a secondary still has another handle open. This coordinator is created and
            // disposed by the same UI thread because Windows mutex ownership is thread-affine.
            try
            {
                if (IsPrimary)
                    ReleasePrimaryMutex(_instanceMutex, _instanceMutexName);
            }
            finally
            {
                _instanceMutex.Dispose();
                _activationWait?.Unregister(null);
                _activationEvent.Dispose();
            }
        }
    }
}
