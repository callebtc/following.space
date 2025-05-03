import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
	plugins: [sveltekit()],
	server: {
		fs: {
			allow: ['cache']
		},
		allowedHosts: ['following.space', 'staging.following.space']
	}
});
