import { type Handle } from '@sveltejs/kit';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';
import { generatePreviewImage } from '$lib/services/preview-image.service';
import { getFollowListById } from '$lib/services/follow-list.service';
import { ndk } from '$lib/nostr/ndk';
import type { FollowList } from '$lib/types/follow-list';

// Debug logging configuration
const DEBUG = true;
const logDebug = (...args: any[]) => {
    if (DEBUG) console.log('[Server Hook]', ...args);
};

// Get the directory name for the current module
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Create a directory for storing generated preview images
// Use an absolute path that doesn't change based on server file location
const CACHE_DIR = path.join(process.cwd(), 'static/preview-images');
if (!fs.existsSync(CACHE_DIR)) {
    fs.mkdirSync(CACHE_DIR, { recursive: true });
}

/**
 * Creates a promise that times out after the specified duration
 * @param promise The promise to race against the timeout
 * @param timeoutMs Timeout duration in milliseconds
 * @param errorMessage Error message to throw on timeout
 */
async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, errorMessage: string): Promise<T> {
    const timeoutPromise = new Promise<T>((_, reject) => {
        setTimeout(() => reject(new Error(errorMessage)), timeoutMs);
    });

    return Promise.race([promise, timeoutPromise]);
}

export const handle: Handle = async ({ event, resolve }) => {
    console.log(`[${event.getClientAddress()}] > `, event.request.url,);
    // log IP address
    const url = new URL(event.request.url);
    const pathname = url.pathname;

    // Only handle paths that match the follow list pattern
    const followListMatch = pathname.match(/^\/d\/([a-zA-Z0-9-]+)$/);

    if (followListMatch) {
        // parse from /d/<listId>?p=<pubKey>
        const listId = followListMatch[1];
        const pubKey = url.searchParams.get('p');
        const userAgent = event.request.headers.get('user-agent') || '';

        // Check if this is a bot or social media crawler, including Signal
        const isCrawler = /bot|facebook|twitter|slack|discord|telegram|linkedin|whatsapp|signal|Amethyst/i.test(userAgent);
        // TEST: always generate image
        if (isCrawler) {
            logDebug('isCrawler', userAgent);
            try {
                // Generate a cached image filename
                const cacheFilename = `${listId}.png`;
                const cacheFollowListMetadataFilename = `${listId}.json`;
                const cachePath = path.join(CACHE_DIR, cacheFilename);
                const cacheFollowListMetadataPath = path.join(CACHE_DIR, cacheFollowListMetadataFilename);
                const relativeImagePath = `/preview-images/${cacheFilename}`;


                // Check if we have a cached metadata file that's less than 24 hours old
                let metadataExists = false;
                if (fs.existsSync(cacheFollowListMetadataPath)) {
                    const stats = fs.statSync(cacheFollowListMetadataPath);
                    const fileAge = Date.now() - stats.mtimeMs;
                    metadataExists = fileAge < 24 * 60 * 60 * 1000; // 24 hours in milliseconds
                    logDebug('Metadata exists since:', new Date(stats.mtimeMs).toISOString(), cacheFollowListMetadataPath);
                }
                let followList: FollowList | null = null;
                // test: fetch 
                if (!metadataExists) {
                    // Fetch the follow list data
                    logDebug('[!metadataExists] Connecting to relays');
                    try {
                        await withTimeout(
                            ndk.connect(3000),
                            3000,
                            'Connection to nostr relays timed out'
                        );

                        followList = await withTimeout(
                            getFollowListById(listId, pubKey ?? undefined),
                            5000,
                            'Fetching follow list data timed out'
                        );

                        if (followList) {
                            fs.writeFileSync(cacheFollowListMetadataPath, JSON.stringify(followList));
                        }
                    } catch (error) {
                        console.error('Error connecting or fetching follow list:', error);
                        // return new Response('Error fetching follow list data: Request timed out', { status: 504 });
                        throw error;
                    }
                } else {
                    followList = JSON.parse(fs.readFileSync(cacheFollowListMetadataPath, 'utf8'));
                }

                if (!followList) {
                    return new Response('Follow list not found', { status: 404 });
                }

                // Check if we have a cached image that's less than 24 hours old
                let imageExists = false;
                if (fs.existsSync(cachePath)) {
                    const stats = fs.statSync(cachePath);
                    const fileAge = Date.now() - stats.mtimeMs;
                    imageExists = fileAge < 24 * 60 * 60 * 1000; // 24 hours in milliseconds
                    logDebug('Image exists since:', new Date(stats.mtimeMs).toISOString(), cachePath);
                }
                if (!imageExists) {
                    // Generate the image if it doesn't exist or is too old
                    // Fetch the follow list data
                    logDebug('[!imageExists] Connecting to relays');
                    try {
                        await withTimeout(
                            ndk.connect(),
                            1000,
                            'Connection to nostr relays timed out'
                        );

                        logDebug('[!imageExists] Generating image');

                        const imagePath = await withTimeout(
                            generatePreviewImage(followList, cachePath),
                            10000,
                            'Generating preview image timed out'
                        );
                        logDebug('[!imageExists] ✅ Image successfully generated', imagePath);
                    } catch (error) {
                        console.error('Error generating preview image:', error);
                        // Fallback to default image or continue without image
                        // We can still serve the page even if image generation fails
                    }
                }
                // Modify the response to include meta tags for social media
                const response = await resolve(event);
                const html = await response.text();

                // Create meta tags for social media sharing - formatted for compatibility with Signal and other platforms
                const metaTags = `
            <meta charset="utf-8" />
            <meta property="og:title" content="Following._ ${followList.name}" />
            <meta property="og:description" content="${followList.description || `A Nostr Follow Pack with ${followList.entries.length} people`}" />
            <meta property="og:image" content="${url.origin.replace('http:', 'https:')}${relativeImagePath}" />
            <meta property="og:url" content="${url.href.replace('http:', 'https:')}" />
            <meta property="og:type" content="website" />
            <meta property="og:site_name" content="Following._" />
            <meta property="og:image:width" content="1200" />
            <meta property="og:image:height" content="630" />
            <meta name="twitter:card" content="summary_large_image" />
            <meta name="twitter:title" content="Following._ ${followList.name}" />
            <meta name="twitter:description" content="${followList.description || `A Nostr Follow Pack with ${followList.entries.length} people`}" />
            <meta name="twitter:image" content="${url.origin.replace('http:', 'https:')}${relativeImagePath}" />
          `;

                // Remove all meta tags with property="og:*" and property="twitter:*" and insert our meta tags into the HTML head
                const updatedHtml = html
                    .replace(/<meta[^>]*property=["']?og:[^"']*["']?[^>]*>/g, '')
                    .replace(/<meta[^>]*property=["']?twitter:[^"']*["']?[^>]*>/g, '')
                    .replace('</head>', `${metaTags}</head>`);

                return new Response(updatedHtml, {
                    status: response.status,
                    headers: response.headers
                });
            } catch (error) {
                logDebug('Error generating social media preview:', error);
                // just resolve the request
                return resolve(event);
            }
        }
    }

    // For non-matching routes or errors, just use the standard response
    return resolve(event);
}; 