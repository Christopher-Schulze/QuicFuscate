// See https://svelte.dev/docs/kit/types#app.d.ts
// for information about these interfaces
declare global {
	namespace App {
		// interface Error {}
		// interface Locals {}
		// interface PageData {}
		// interface PageState {}
		// interface Platform {}
	}
}

export {};

/// Release version injected by Vite from the workspace package version in the root Cargo.toml.
/// See `releaseVersion()` in vite.config.ts and scripts/audits/verify-release-version.sh.
declare const __RELEASE_VERSION__: string;
