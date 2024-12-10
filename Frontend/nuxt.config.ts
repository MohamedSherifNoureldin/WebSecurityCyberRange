import obfuscatorPlugin from "vite-plugin-javascript-obfuscator";

export default defineNuxtConfig({
  extends: ['@nuxt/ui-pro'],
  future: {
    compatibilityVersion: 4,
  },
  modules: [
     '@nuxt/ui',
    '@nuxt/fonts',
    '@vueuse/nuxt',
    '@nuxtjs/color-mode',
    '@nuxt/image',
    'nuxt-countdown',
    'nuxt-tiptap-editor'
  ],

  css: ['@xterm/xterm/css/xterm.css'],

  experimental: {
    typedPages: true
  },

  telemetry: false,
  tiptap: {
    prefix: 'Tiptap', // prefix for Tiptap imports, composables not included
  },
  ui: {
    global: true,
    safelistColors: [
      'primary',
      'red',
      'orange',
      'green',
      'sky',
      'blue',
      'indigo',
      'purple',
      'pink',
      'lime',
      'fuchsia',
      'yellow',
      'cyan',
      'teal',
      'emerald',
      'rose',
      'amber',
      'violet',
      'gray'
    ],
  },

  devtools: {
    enabled: false
  },

  $development: {
    sourcemap: {
      server: true,
      client: true
    },
    typescript: {
      strict: false,
      typeCheck: false,
      shim: false,
      tsConfig: {
        compilerOptions: {
          verbatimModuleSyntax: false,
          emitDecoratorMetadata: true,
          experimentalDecorators: true,
          skipLibCheck: true,
        },
      },
    },
  },

  runtimeConfig: {
    public: {
      apiURL: process.env.API_URL,
      wsURL: process.env.WS_URL,
      serverURL: process.env.SERVER_URL
    }
  },

  vite: {
    esbuild: {
      tsconfigRaw: {
        compilerOptions: {
          experimentalDecorators: true
        }
      }
    },
    // plugins: [
    //    obfuscatorPlugin({
    //       apply: "build",
    //      debugger: true,
    //      options: {
    //         debugProtection: true,
    //      },
    //    }),
    //  ],
  },

  tailwindcss: {
    viewer: false
  },

  compatibilityDate: '2024-07-15',

  icon: {
    componentName: 'UIcon',
    collections: ['heroicons', 'octicon', 'simple-icons']
  }
})
