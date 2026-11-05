# Nostr Follow List

A minimalistic Nostr application for creating, sharing, and discovering Nostr Follow Packs.

## Tech Stack

- [SvelteKit](https://kit.svelte.dev/) - Frontend framework
- [TypeScript](https://www.typescriptlang.org/) - Type-safe JavaScript
- [Tailwind CSS](https://tailwindcss.com/) - Utility-first CSS framework
- [Applesauce](https://applesauce.build) - EventStore, loaders, relay pool, accounts, signers and content parsing
- [RxJS](https://rxjs.dev/) - Shared reactive queries and cancellable loading sessions

## Getting Started

### Prerequisites

- Node.js 22 or newer
- npm

### Installation

1. Clone the repository:

```bash
git clone https://github.com/callebtc/nostr-follow-packs.git
cd nostr-follow-packs
```

2. Install dependencies:

```bash
npm install
```

3. Start the development server:

```bash
npm run dev
```

4. Open your browser and navigate to `http://localhost:5173`

## Building for Production

To create a production version of the app:

```bash
npm run build
```

You can preview the production build with `npm run preview`.

## How It Works

- Users can log in with a NIP-07 browser extension, an nsec, or a NIP-46 bunker/QR session
- Create follow lists by searching for users and adding them to a list
- Publish follow lists as replaceable events (kind 39089)
- Browse and discover follow lists created by others
- View follow lists and follow users directly from them
- Configure account lookup relays and Blossom media servers in Settings
- Upload pack cover images to Blossom servers
- Use a light or dark theme that follows your system preference

## Architecture and sessions

A shared browser EventStore receives cached, loaded, live and acknowledged local events. Svelte observes that store through RxJS-backed readables. An application-wide directory sync hydrates cached packs, reconciles history with NIP-77/paginated REQ fallback, and shares live updates across routes and filters. Pack history starts with a finite range and expands on demand; account metadata uses the same sync loader. Member posts use a bounded selection of NIP-65 outbox relays.

AccountManager owns authentication. Extension identity survives reloads. Raw nsec keys remain in memory; signing in again is required after a reload. Remote signer credentials are stored in sessionStorage for the current tab. Existing compatible logins and account-scoped follow snapshots migrate automatically; older remote signer payloads may need pairing again. Logout preserves follow snapshots and unrelated browser preferences.

Server previews use a separate, bounded read-only Applesauce runtime and close its connections after each request. Generated images live in `.cache/previews` and are served through a dedicated route, keyed by pack author, identifier and revision. The server needs write access to that cache directory.

## Checks

```bash
npm run check
npm test
npm run build
```

The controlled browser smoke test uses generated keys and simulated cache/relay responses. It never publishes to public relays:

```bash
npx playwright install chromium
npm run preview -- --host 127.0.0.1 --port 5188
# In another terminal:
npm run test:browser
```

Set `BASE_URL` to use another preview URL or `CHROMIUM_EXECUTABLE` to use an existing browser binary. Build before starting the preview. Remote signer integration tests use a real Applesauce provider over an in-memory transport; hardware/extensions and public relay behavior still warrant deployment smoke testing.

## Nostr Follow List Event Format

Follow lists are published as Nostr events with `kind: 39089`. This is a parameterized replaceable event that allows users to maintain multiple follow lists.

### Event Structure

```json
{
  "kind": 39089,            // The event kind for follow lists
  "pubkey": "...",          // Public key of the list creator
  "created_at": 1234567890, // Unix timestamp when the list was created/updated
  "tags": [
    ["title", "List Title"], // Title of the follow list
    ["d", "uuid"],           // Unique identifier for the list (for replaceability)
    ["image", "https://..."], // Optional: URL to an image for the list
    ["description", "..."],   // Optional: Description of the follow list
    ["p", "pubkey1"],        // Public key of a user in the follow list
    ["p", "pubkey2"],        // Each "p" tag represents a user in the list
    // Additional "p" tags for more users
  ],
  "content": "",            // Usually empty
  "sig": "..."              // Signature of the event
}
```

### Field Descriptions

- **kind**: 39089 - Specific kind for follow lists
- **pubkey**: The public key of the user who created the list
- **created_at**: Unix timestamp when the list was created or last updated
- **tags**: Array of tags with special meanings:
  - `["title", "..."]`: The name/title of the follow list
  - `["d", "..."]`: A unique identifier for the list (usually a UUID), allows for updating the list later
  - `["image", "..."]`: Optional URL to an image representing the list
  - `["description", "..."]`: Optional text description of the follow list
  - `["p", "..."]`: Each "p" tag contains the public key of a user included in the follow list
- **content**: Usually empty
- **sig**: The cryptographic signature proving the event's authenticity

### Implementation Notes

- Follow lists are parameterized replaceable events, identified by the combination of pubkey, kind, and d-tag
- To update a list, publish a new event with the same kind, pubkey, and d-tag values but a newer created_at timestamp
- To follow multiple users in a list, add multiple "p" tags to the event
- Clients should display lists ordered by most recent created_at

## Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/callebtc/nostr-follow-packs/issues).

## License

This project is licensed under the MIT License - see the LICENSE file for details.
