const esbuild = require('esbuild');
const { execSync } = require('child_process');

const commit = execSync('git rev-parse --short HEAD').toString().trim();

esbuild.build({
  entryPoints: ['agent/init.ts'],
  bundle: true,
  format: 'iife',
  platform: 'neutral',
  target: 'es2020',
  outfile: 'script.js',
  define: {
    ISDEV: 'false',
    COMMIT: `"${commit}"`,
  },
  logLevel: 'info',
}).catch((e) => {
  console.error(e);
  process.exit(1);
});
