#![allow(unused_macros)]

#[cfg(feature = "slog")]
pub use slog::Logger;

#[cfg(not(feature = "slog"))]
#[derive(Clone)]
pub struct Logger;

#[cfg(feature = "slog")]
macro_rules! trace {
    ( $l:expr, $( $args:tt )* ) => {
        slog::trace!( $l, $( $args )* )
    };
}

#[cfg(feature = "slog")]
macro_rules! debug {
    ( $l:expr, $( $args:tt )* ) => {
        slog::debug!( $l, $( $args )* )
    };
}

#[cfg(feature = "slog")]
macro_rules! info {
    ( $l:expr, $( $args:tt )* ) => {
        slog::info!( $l, $( $args )* )
    };
}

#[cfg(feature = "slog")]
macro_rules! warn {
    ( $l:expr, $( $args:tt )* ) => {
        slog::warn!( $l, $( $args )* )
    };
}

#[cfg(feature = "slog")]
macro_rules! error {
    ( $l:expr, $( $args:tt )* ) => {
        slog::error!( $l, $( $args )* )
    };
}

#[cfg(not(feature = "slog"))]
macro_rules! log {
    ( @ { $( $args:expr )* }, $l:expr, $lvl:expr, $fmt:expr, $arg:expr; $( $rest:tt )* ) => {
        log!( @ { $( $args )* $arg }, $l, $lvl, $fmt; $( $rest )*)
    };
    ( @ { $( $args:expr )* }, $l:expr, $lvl:expr, $fmt:expr, $arg:expr, $( $rest:tt )* ) => {
        log!( @ { $( $args )* $arg }, $l, $lvl, $fmt, $( $rest )*)
    };
    ( @ { $( $args:expr )* }, $l:expr, $lvl:expr, $fmt:expr, $arg:expr ) => {
        log!( @ { $( $args )* $arg }, $l, $lvl, $fmt)
    };



    ( @ { $( $args:expr )* }, $l:expr, $lvl:expr, $fmt:expr; $k:literal => $v:expr, $( $rest:tt )* ) => {
        log!( @ { $( $args )* $k $v }, $l, $lvl, concat!($fmt, " {}={}"); $( $rest )* )
    };
    ( @ { $( $args:expr )* }, $l:expr, $lvl:expr, $fmt:expr; $k:literal => %$v:expr, $( $rest:tt )* ) => {
        log!( @ { $( $args )* $k $v }, $l, $lvl, concat!($fmt, " {}={}"); $( $rest )* )
    };
    ( @ { $( $args:expr )* }, $l:expr, $lvl:expr, $fmt:expr; $k:literal => ?$v:expr, $( $rest:tt )* ) => {
        log!( @ { $( $args )* $k $v }, $l, $lvl, concat!($fmt, " {}={:?}"); $( $rest )* )
    };
    ( @ { $( $args:expr )* }, $l:expr, $lvl:expr, $fmt:expr; $k:literal => $v:expr ) => {
        log!( @ { $( $args )* $k $v }, $l, $lvl, concat!($fmt, " {}={}") )
    };
    ( @ { $( $args:expr )* }, $l:expr, $lvl:expr, $fmt:expr; $k:literal => %$v:expr ) => {
        log!( @ { $( $args )* $k $v }, $l, $lvl, concat!($fmt, " {}={}") )
    };
    ( @ { $( $args:expr )* }, $l:expr, $lvl:expr, $fmt:expr; $k:literal => ?$v:expr ) => {
        log!( @ { $( $args )* $k $v }, $l, $lvl, concat!($fmt, " {}={:?}") )
    };



    ( @ { $( $args:expr )* }, $l:expr, $lvl:expr, $fmt:expr; ) => {
        log!( @ { $( $args )* }, $l, $lvl, $fmt)
    };
    ( @ { $( $args:expr )* }, $l:expr, $lvl:expr, $fmt:expr; ) => {
        log!( @ { $( $args )* }, $l, $lvl, $fmt)
    };
    ( @ { $( $args:expr )* }, $l:expr, $lvl:expr, $fmt:expr, ) => {
        log!( @ { $( $args )* }, $l, $lvl, $fmt)
    };



    ( @ { $( $args:expr )* }, $l:expr, $lvl:expr, $fmt:expr ) => {
        {
            let _ = $l;

            #[cfg(not(feature = "log"))]
            {
                $(
                    let _ = $args;
                )*
            }

            #[cfg(feature = "log")]
            log::log!( $lvl, $fmt, $( $args, )* )
        }
    };



    ( $l:expr, $lvl:expr, $( $args:tt )* ) => {
        log!( @ {}, $l, $lvl, $( $args )* )
    };
}

#[cfg(not(feature = "slog"))]
macro_rules! trace {
    ( $l:expr, $( $args:tt )* ) => {
        #[cfg(feature = "log")]
        {
            log!( $l, log::Level::Trace, $( $args )* )
        }

        #[cfg(not(feature = "log"))]
        {
            log!( $l, (), $( $args )* )
        }
    };
}

#[cfg(not(feature = "slog"))]
macro_rules! debug {
    ( $l:expr, $( $args:tt )* ) => {
        #[cfg(feature = "log")]
        {
            log!( $l, log::Level::Debug, $( $args )* )
        }

        #[cfg(not(feature = "log"))]
        {
            log!( $l, (), $( $args )* )
        }
    };
}

#[cfg(not(feature = "slog"))]
macro_rules! info {
    ( $l:expr, $( $args:tt )* ) => {
        #[cfg(feature = "log")]
        {
            log!( $l, log::Level::Info, $( $args )* )
        }

        #[cfg(not(feature = "log"))]
        {
            log!( $l, (), $( $args )* )
        }
    };
}

#[cfg(not(feature = "slog"))]
macro_rules! warn {
    ( $l:expr, $( $args:tt )* ) => {
        #[cfg(feature = "log")]
        {
            log!( $l, log::Level::Warn, $( $args )* )
        }

        #[cfg(not(feature = "log"))]
        {
            log!( $l, (), $( $args )* )
        }
    };
}

#[cfg(not(feature = "slog"))]
macro_rules! error {
    ( $l:expr, $( $args:tt )* ) => {
        #[cfg(feature = "log")]
        {
            log!( $l, log::Level::Error, $( $args )* )
        }

        #[cfg(not(feature = "log"))]
        {
            log!( $l, (), $( $args )* )
        }
    };
}
