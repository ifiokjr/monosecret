/// <reference types="astro/client" />

// Starlight 0.42 resolves `virtual:starlight/user-config` at build time but no
// longer ships a type declaration for it, which makes `astro check` fail on any
// component override that reads the resolved config. Tie the declaration to
// Starlight's own exported type so the shape cannot drift from the package.
declare module 'virtual:starlight/user-config' {
  const config: import('@astrojs/starlight/types').StarlightConfig;
  export default config;
}
