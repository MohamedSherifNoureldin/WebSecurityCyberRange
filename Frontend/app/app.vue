<template>
  <div>
    <NuxtLoadingIndicator />

    <NuxtLayout>
      <NuxtPage />
    </NuxtLayout>

    <UNotifications />
    <UModals />
  </div>
</template>

<script setup lang="ts">
const colorMode = useColorMode()

const color = computed(() =>
  colorMode.value === 'dark' ? '#111827' : 'white'
)

useHead({
  meta: [
    { charset: 'utf-8' },
    { name: 'viewport', content: 'width=device-width, initial-scale=1' },
    { key: 'theme-color', name: 'theme-color', content: color }
  ],
  link: [{ rel: 'icon', href: colorMode.value === 'dark' ? '/favicon-dark.ico' : '/favicon-light.ico' }],
  htmlAttrs: {
    lang: 'en'
  }
})

const title = 'AUC | Cyberrange'
const description
  = 'The American University in Cairo Cyber Range is a platform for cybersecurity training and competitions.'

useSeoMeta({
  title,
  description,
  ogTitle: title,
  ogDescription: description
})
</script>
