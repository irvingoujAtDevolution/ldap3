#[macro_export]
macro_rules! to_js_error {
    ($($arg:tt)*) => {
        JsValue::from_str(&format!($($arg)*))
    };
}
