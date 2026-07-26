//! Shared Dioxus UI primitives and theming for QuicFuscate desktop and admin apps.

pub mod components;
pub mod theme;
pub mod types;

pub mod format;
pub mod validators;
pub mod qkey_utils;
pub mod policy_display;
pub mod domain_fronting;

pub mod prelude {
    pub use crate::{GlassCard, NavPill, Sidebar, SidebarNavTab, Switch, TextInput, ThemeProvider, ThroughputChart};
}

pub use components::*;
pub use theme::*;
pub use types::*;
