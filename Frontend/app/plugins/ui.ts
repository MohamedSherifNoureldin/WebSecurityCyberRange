import colors from '#tailwind-config/theme/colors'

export default defineNuxtPlugin({

  enforce: 'post',
  setup() {
    function hexToRgb(hex: string) {
      const shorthandRegex = /^#?([a-f\d])([a-f\d])([a-f\d])$/i
      hex = hex.replace(shorthandRegex, function (_, r, g, b) {
        return r + r + g + g + b + b
      })

      const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex)
      return result
        ? `${parseInt(result[1] as string, 16)} ${parseInt(result[2] as string, 16)} ${parseInt(result[3] as string, 16)}`
        : null
    }

    const appConfig = useAppConfig()

    const root = computed(() => {
      const appConfig = useAppConfig()
      const primary = colors[appConfig.ui.primary as keyof typeof colors]
      const gray = colors[appConfig.ui.gray as keyof typeof colors]

      return `:root {
        ${Object.entries(primary || colors.green).map(([key, value]) => `--color-primary-${key}: ${hexToRgb(value)};`).join('\n')}
        --color-primary-DEFAULT: var(--color-primary-500);

        ${Object.entries(gray || colors.cool).map(([key, value]) => `--color-gray-${key}: ${hexToRgb(value)};`).join('\n')}
        }

        .dark {
          --color-primary-DEFAULT: var(--color-primary-400);
        }
        `
    })

    if (import.meta.client) {
      watch(root, () => {
        window.localStorage.setItem('nuxt-ui-root', root.value)
      })

      appConfig.ui.primary = window.localStorage.getItem('nuxt-ui-primary') || appConfig.ui.primary
      appConfig.ui.gray = window.localStorage.getItem('nuxt-ui-gray') || appConfig.ui.gray
    }
    if (import.meta.server) {
      useHead({
        script: [
          {
            innerHTML: `
                if (localStorage.getItem('nuxt-ui-root')) {
                  document.querySelector('style#nuxt-ui-colors').innerHTML = localStorage.getItem('nuxt-ui-root')
                }`.replace(/\s+/g, ' '),
            type: 'text/javascript',
            tagPriority: -1
          }
        ]
      })
    }
  }
})
