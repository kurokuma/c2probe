//! Process-wide Ctrl+C handling.
//!
//! `tokio::signal::ctrl_c` only completes for signals received *after* the returned
//! future is first polled, and the OS handler it installs is never uninstalled. A
//! listener that is created and dropped inside a loop therefore both misses signals
//! that arrive between iterations and, once the loop ends, leaves the process unable
//! to be interrupted at all. The listener is registered once here instead, and every
//! stage observes the same [`Shutdown`] handle.

use std::sync::Arc;

use tokio::sync::watch;

#[derive(Debug, Clone)]
pub struct Shutdown {
    // Held so that `changed()` never fails while any handle is alive.
    _tx: Arc<watch::Sender<bool>>,
    rx: watch::Receiver<bool>,
}

impl Shutdown {
    /// Registers the single process-wide Ctrl+C listener.
    ///
    /// The first signal requests a graceful stop; a second one aborts immediately so
    /// an operator is never left without a way out.
    pub fn listen() -> Self {
        let handle = Self::inactive();
        let tx = handle._tx.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_err() {
                return;
            }
            eprintln!("shutdown requested; stopping new work (press Ctrl+C again to abort)");
            let _ = tx.send(true);
            if tokio::signal::ctrl_c().await.is_ok() {
                eprintln!("second interrupt; aborting without flushing pending output");
                std::process::exit(130);
            }
        });
        handle
    }

    /// A handle that never fires, for call sites that do not install a listener.
    pub fn inactive() -> Self {
        let (tx, rx) = watch::channel(false);
        Self {
            _tx: Arc::new(tx),
            rx,
        }
    }

    pub fn is_triggered(&self) -> bool {
        *self.rx.borrow()
    }

    /// Requests the same graceful stop as the first Ctrl+C, for internal task errors.
    pub fn request(&self) {
        let _ = self._tx.send(true);
    }

    /// Resolves when shutdown has been requested, and stays resolved afterwards.
    pub async fn wait(&mut self) {
        while !*self.rx.borrow_and_update() {
            if self.rx.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn inactive_handle_never_triggers() {
        let mut shutdown = Shutdown::inactive();
        assert!(!shutdown.is_triggered());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), shutdown.wait())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn triggered_handle_stays_resolved() {
        let handle = Shutdown::inactive();
        handle.request();
        let mut first = handle.clone();
        first.wait().await;
        assert!(first.is_triggered());
        // A second wait must not block once shutdown has been requested.
        first.wait().await;
    }
}
