// See https://kit.svelte.dev/docs/types#app
// for information about these interfaces
declare global {
  interface Window {
    nostr?: import('applesauce-signers').ISigner;
  }
	namespace App {
		// interface Error {}
		// interface Locals {}
		// interface PageData {}
		// interface Platform {}
	}
}

// This adds node global types to our SvelteKit app for server-only features
declare module 'node:fs';
declare module 'node:path';
declare module 'node:url';

export { };
