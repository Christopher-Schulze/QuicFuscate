#[cfg(test)]
mod tests {
    #[test]
    fn fixture_only() {
        unsafe {
            std::ptr::read_volatile(std::ptr::null());
        }
        let _ = Box::leak(Box::new(1_u8));
    }
}
