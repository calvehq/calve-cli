//! Lease keeping for every execution Calve runs itself (M5 lease experiments): a lease is
//! renewed for the whole run, so a slow step (a whole-Project digest or a long effect or
//! observation loop on a loaded machine) never outlives it and gets the execution LOST.
use std::time::Duration;

use openaevc_sdk::TypedClient as _;

/// Renews a lease every heartbeat interval from its own thread until dropped, so a slow step
/// (a whole-Project digest on a loaded machine, a stalled disk write) never outlives it. The
/// embedded runtime is called directly, so renewal does not wait for this task to be scheduled.
pub(crate) struct LeaseKeeper {
    stop: std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl LeaseKeeper {
    /// The keeper, unless disabled by `CALVE_TEST_NO_LEASE_KEEPER=1` (debug builds; the control
    /// experiment).
    pub(crate) fn maybe(
        client: crate::client::Client,
        lease: openaevc::protocol::Lease,
    ) -> Option<Self> {
        (!(cfg!(debug_assertions)
            && std::env::var("CALVE_TEST_NO_LEASE_KEEPER").is_ok_and(|v| v == "1")))
        .then(|| Self::start(client, lease))
    }

    pub(crate) fn start(client: crate::client::Client, lease: openaevc::protocol::Lease) -> Self {
        let stop = std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let every = Duration::from_millis(lease.heartbeat_interval_ms.max(100));
        let flag = stop.clone();
        let thread = std::thread::spawn(move || {
            // Its own runtime: embedded commands run through spawn_blocking on the caller's
            // runtime, and the main one may be blocked by the very step being outlived.
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            let (lock, cv) = &*flag;
            let mut stopped = lock.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                let (s, timeout) = cv
                    .wait_timeout(stopped, every)
                    .unwrap_or_else(|e| e.into_inner());
                stopped = s;
                if *stopped {
                    return;
                }
                if timeout.timed_out() {
                    drop(stopped);
                    let t = std::time::Instant::now();
                    let r = rt.block_on(client.heartbeat(&lease));
                    // Debug builds: renewal timing and failures, for the lease experiments.
                    if cfg!(debug_assertions) && std::env::var_os("CALVE_TEST_KEEPER_LOG").is_some()
                    {
                        eprintln!(
                            "lease keeper: heartbeat in {:?}: {:?}",
                            t.elapsed(),
                            r.as_ref().err()
                        );
                    }
                    stopped = lock.lock().unwrap_or_else(|e| e.into_inner());
                }
            }
        });
        LeaseKeeper {
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for LeaseKeeper {
    fn drop(&mut self) {
        let (lock, cv) = &*self.stop;
        *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
        cv.notify_all();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
