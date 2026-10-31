//! Logging over RTT with the `defmt` feature, compiled out without it.

#![expect(clippy::arbitrary_source_item_ordering, reason = "a macro must be defined before its re-export")]

/// Logs at info level.
macro_rules! info {
    ($fmt:literal $(, $arg:expr)* $(,)?) => {{
        #[cfg(feature = "defmt")]
        {
            defmt::info!($fmt $(, $arg)*);
        }
        #[cfg(not(feature = "defmt"))]
        {
            $(_ = &$arg;)*
        }
    }};
}

pub(crate) use info;
