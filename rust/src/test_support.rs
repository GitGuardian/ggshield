use std::sync::{Mutex, MutexGuard};

static PROCESS_STATE: Mutex<()> = Mutex::new(());

pub fn exclusive() -> MutexGuard<'static, ()> {
    PROCESS_STATE.lock().unwrap_or_else(|e| e.into_inner())
}
