//! VisionOS glassmorphism theming provider.
//!
//! Reuses the existing `@quicfuscate/theme` CSS tokens by loading the compiled
//! stylesheet into the document head. Components reference the same CSS custom
//! properties so the visual language stays identical to the Svelte apps.

use dioxus::prelude::*;

/// Asset path to the pre-built theme CSS.
///
/// Consumers must ensure `assets/theme.css` exists before launching the app.
/// For desktop this is normally produced by `bun tailwindcss` from
/// `packages/theme/index.css`; for web `dx` can build it via `Dioxus.toml`.
pub const THEME_CSS: Asset = asset!("/assets/theme.css");

/// Loads the shared theme stylesheet once at the root of the app.
#[component]
pub fn ThemeProvider(children: Element) -> Element {
    rsx! {
        document::Stylesheet { href: THEME_CSS }
        {children}
    }
}
