import { build } from 'esbuild';

async function buildModule() {
    const shared = {
        platform: 'node',
        entryPoints: ['source/index.ts'],
        bundle: true,
        minify: true,
        treeShaking: true,
        sourcemap: true
    };

    await build({
        ...shared,
        outfile: 'bundled/index.cjs',
        format: 'cjs',
    });
}
await buildModule();