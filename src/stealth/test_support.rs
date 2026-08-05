use std::env;
use std::ffi::OsString;

pub struct EnvGuard {
    key: &'static str,
    prev: Option<OsString>,
}

impl EnvGuard {
    pub fn set(key: &'static str, val: &str) -> Self {
        let prev = env::var_os(key);
        unsafe {
            env::set_var(key, val);
        }
        Self { key, prev }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.prev.take() {
            Some(v) => unsafe {
                env::set_var(self.key, v);
            },
            None => unsafe {
                env::remove_var(self.key);
            },
        }
    }
}

pub fn acquire_env_lock() -> std::sync::MutexGuard<'static, ()> {
    crate::env_utils::test_support::acquire_env_lock()
}
