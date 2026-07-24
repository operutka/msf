use std::{
    future::IntoFuture,
    sync::{Arc, LazyLock, Mutex},
    time::Duration,
};

use tokio::time::Instant;

static GLOBAL_TRANSACTION_TIMER: LazyLock<InternalTransactionTimer> =
    LazyLock::new(|| InternalTransactionTimer::new(false, Duration::from_millis(5)));

/// Timer for pacing STUN Binding requests used for gathering candidates and
/// connectivity checks.
#[derive(Clone)]
pub struct TransactionTimer {
    inner: Arc<InternalTransactionTimer>,
}

impl TransactionTimer {
    /// Create a new transaction timer.
    pub fn new(global_limit: bool, ta: Duration) -> Self {
        Self {
            inner: Arc::new(InternalTransactionTimer::new(global_limit, ta)),
        }
    }

    /// Create a new transaction token.
    pub fn create_transaction_token(&self) -> TransactionToken {
        self.inner.create_transaction_token()
    }
}

impl Default for TransactionTimer {
    fn default() -> Self {
        Self::new(true, Duration::from_millis(50))
    }
}

/// Internal transaction timer context.
struct InternalTransactionTimer {
    next: Mutex<Instant>,
    ta: Duration,
    global_limit: bool,
}

impl InternalTransactionTimer {
    /// Create a new internal transaction timer context.
    fn new(global_limit: bool, ta: Duration) -> Self {
        Self {
            next: Mutex::new(Instant::now()),
            ta,
            global_limit,
        }
    }

    /// Create a new transaction token.
    fn create_transaction_token(&self) -> TransactionToken {
        let nti = self.next_transaction_instant();

        let global = if self.global_limit {
            Some(&*GLOBAL_TRANSACTION_TIMER)
        } else {
            None
        };

        TransactionToken { nti, global }
    }

    /// Get the next transaction instant.
    fn next_transaction_instant(&self) -> Instant {
        let mut next = self.next.lock().unwrap();

        let res = next.max(Instant::now());

        *next = res + self.ta;

        res
    }
}

/// Transaction token.
pub struct TransactionToken {
    nti: Instant,
    global: Option<&'static InternalTransactionTimer>,
}

impl TransactionToken {
    /// Await the assigned transaction time slot.
    pub async fn await_transaction_slot(self) {
        tokio::time::sleep_until(self.nti.into()).await;

        if let Some(global) = self.global {
            tokio::time::sleep_until(global.next_transaction_instant()).await
        }
    }

    /// Run a given future after awaiting the assigned transaction time slot.
    pub async fn perform_transaction<F, R>(self, f: F) -> R
    where
        F: IntoFuture<Output = R>,
    {
        self.await_transaction_slot().await;

        f.await
    }
}
