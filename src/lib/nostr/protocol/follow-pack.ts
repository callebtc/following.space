import { FOLLOW_LIST_KIND } from './kinds';
export { FOLLOW_LIST_KIND } from './kinds';

/** Plain protocol input keeps parsing independent of clients and UI frameworks. */
export interface PackEvent {
    id: string;
    pubkey: string;
    kind?: number;
    created_at?: number;
    tags: string[][];
    content: string;
}

export interface FollowListEntry {
    pubkey: string;
    relay?: string;
    name?: string;
    picture?: string;
    npub?: string;
    bio?: string;
    nip05?: string;
    nip05Verified?: boolean;
}

export interface FollowList {
    id: string;
    eventId: string;
    name: string;
    coverImageUrl: string;
    pubkey: string;
    entries: FollowListEntry[];
    createdAt: number;
    authorName?: string;
    authorPicture?: string;
    description?: string;
}

/**
 * Parse a Nostr event into a FollowList object
 */
export function parseFollowListEvent(event: PackEvent): FollowList | null {
    try {
        if (event.kind !== FOLLOW_LIST_KIND) return null;
        // Get the name from the title tag
        const titleTag = event.tags.find(tag => tag[0] === 'title');
        // backwards compat: n tag instead of title tag
        const nTag = event.tags.find(tag => tag[0] === 'n');
        const name = titleTag && titleTag[1] ? titleTag[1] : (nTag && nTag[1] ? nTag[1] : 'Untitled Follow Pack');

        // Get the id from the d tag
        const dTag = event.tags.find(tag => tag[0] === 'd');
        const id = dTag?.[1] ?? '';

        // Get the cover image from the image tag
        const imageTag = event.tags.find(tag => tag[0] === 'image');
        const coverImageUrl = imageTag && imageTag[1] ? imageTag[1] : '';

        // Parse the content (JSON with description)
        let description = '';
        // if "description" tag exists, use it
        const descriptionTag = event.tags.find(tag => tag[0] === 'description');
        if (descriptionTag && descriptionTag[1]) {
            description = descriptionTag[1];
        } else {
            // back compat for old follow lists
            try {
                const content = JSON.parse(event.content);
                description = typeof content?.description === 'string' ? content.description : '';
            } catch (e) {
                description = '';
            }
        }

        // Parse the content (JSON with keys array)
        let entries: FollowListEntry[] = [];

        // Get the entries from the p tags
        const pTags = event.tags.filter(tag => tag[0] === 'p' && /^[a-f0-9]{64}$/i.test(tag[1] || ''));
        if (pTags.length > 0 && entries.length === 0) {
            entries = pTags.map(tag => ({
                pubkey: tag[1],
                relay: tag[2] || '',
            }));
        }

        return {
            id,
            eventId: event.id,
            name,
            coverImageUrl,
            pubkey: event.pubkey,
            entries,
            createdAt: event.created_at || 0,
            description,
        };
    } catch (error) {
        console.error('Error parsing follow list event:', error);
        return null;
    }
}


/** A revision id is not the identity of an addressable pack. */
export function packAddress(pack: Pick<FollowList, 'pubkey' | 'id'>): string {
    return `${FOLLOW_LIST_KIND}:${pack.pubkey}:${pack.id}`;
}
