import { packHref } from '../../nostr/protocol/pack-link';
import { createHash } from 'node:crypto';
import { FOLLOW_LIST_KIND, type FollowList } from '../../nostr/protocol/follow-pack';
export function previewKey(pack: FollowList) {
  return createHash('sha256').update(`v2:${FOLLOW_LIST_KIND}:${pack.pubkey}:${pack.id}:${pack.eventId}`).digest('hex');
}
export function escapeAttribute(value: string) {
  return value.replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]!);
}
export function previewMeta(pack: FollowList, origin: string, image: string) {
  const values = {
    'og:title': `Following._ ${pack.name}`, 'og:description': pack.description || `A Nostr Follow Pack with ${pack.entries.length} people`,
    'og:type': 'website', 'og:image': `${origin}${image}`,
    'og:url': `${origin}${packHref(pack)}`,
    'twitter:card': 'summary_large_image', 'twitter:title': `Following._ ${pack.name}`,
    'twitter:description': pack.description || 'A Nostr Follow Pack', 'twitter:image': `${origin}${image}`
  };
  return Object.entries(values).map(([key, value]) => `<meta ${key.startsWith('twitter:') ? 'name' : 'property'}="${key}" content="${escapeAttribute(value)}" />`).join('\n');
}
