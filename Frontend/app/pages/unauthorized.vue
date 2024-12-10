<script setup lang="ts">
import type { NuxtError } from '#app'

useSeoMeta({
  title: 'Unauthorized',
  description: 'You are not authorized to view this page.'
})

defineProps({
  error: {
    type: Object as PropType<NuxtError>,
    required: true
  }
})

useHead({
  htmlAttrs: {
    lang: 'en'
  }
})
</script>

<template>
  <div>
    <UMain>
      <UContainer>
        <UPage>
          <UPageError
            :status="403"
            name="Nah, fam 🙅‍♂️"
            message="I told you hack the labs, not the website! 🤦‍♂️"
          />
        </UPage>
      </UContainer>
    </UMain>

    <UNotifications />
  </div>
</template>
