// Keep discovery, metadata lookup, search, and remote signing as separate roles.
export const APP_RELAYS = [
  'wss://relay.primal.net', 'wss://nos.lol', 'wss://relay.damus.io',
  'wss://relay.ditto.pub', 'wss://relay.nostr.net',
  'wss://nostr.wine', 'wss://nostr.mom', 'wss://theforest.nostr1.com'
];
export const LOOKUP_RELAYS = ['wss://purplepag.es', 'wss://relay.vertexlab.io'];
export const SEARCH_RELAYS = ['wss://search.nos.today', 'wss://relay.nostr.band', 'wss://relay.noswhere.com'];
export const SIGNER_RELAYS = ['wss://bucket.coracle.social', 'wss://relay.nsec.app'];
