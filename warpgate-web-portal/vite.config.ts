import { svelte } from '@sveltejs/vite-plugin-svelte'
import { defineConfig } from 'vite'

// https://vitejs.dev/config/
export default defineConfig({
    plugins: [svelte()],
    base: '/@warpgate/portal',
    build: {
        sourcemap: true,
        manifest: true,
        rollupOptions: {
            input: {
                portal: 'src/portal/index.html',
            },
        },
    },
    resolve: {
        tsconfigPaths: true,
    },
})
