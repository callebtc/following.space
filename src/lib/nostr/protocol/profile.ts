import { getProfileContent, type NostrEvent } from 'applesauce-core/helpers';
export interface ProfileView { name?: string; picture?: string; bio?: string; nip05?: string }
const text = (...values: unknown[]) => values.find((value): value is string => typeof value === 'string' && !!value.trim());
export function parseProfile(event?: NostrEvent): ProfileView {
  if (!event) return {};
  try {
    const content = getProfileContent(event);
    const picture = text(content?.picture, content?.image);
    let safePicture: string | undefined;
    if (picture) { const url = new URL(picture); if (['http:', 'https:'].includes(url.protocol)) safePicture = url.href; }
    return { name: text(content?.display_name, content?.name, content?.displayName), picture: safePicture,
      bio: text(content?.about), nip05: text(content?.nip05) };
  } catch { return {}; }
}
