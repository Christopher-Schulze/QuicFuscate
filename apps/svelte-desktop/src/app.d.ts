// See https://svelte.dev/docs/kit/types#app.d.ts
// for information about these interfaces
declare global {
	/// Release version injected by Vite from the workspace package version in the root Cargo.toml.
	/// See `releaseVersion()` in vite.config.ts and scripts/audits/verify-release-version.sh.
	/// It must be declared inside `declare global`: this file is a module because of the
	/// `export {}` below, so a top-level `declare const` is module-scoped and invisible to
	/// the components that read it.
	const __RELEASE_VERSION__: string;

	namespace App {
		// interface Error {}
		// interface Locals {}
		// interface PageData {}
		// interface PageState {}
		// interface Platform {}
	}
}

export {};
