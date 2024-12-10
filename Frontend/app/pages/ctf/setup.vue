<script setup lang="ts">
definePageMeta({
  layout: 'dashboard'
})

const links = [
  [
    {
      label: 'General',
      icon: 'i-heroicons-user-circle',
      to: '/ctf/setup',
      exact: true
    },
    {
      label: 'Jeopardy',
      icon: 'i-heroicons-puzzle-piece',
      to: '/ctf/setup/jeopardy'
    },

  ]
]
</script>

<template>
  <UDashboardPage>
    <UDashboardPanel grow>

      <UDashboardToolbar class="overflow-x-auto px-1.5 py-0">
        <UHorizontalNavigation :links="links" />
      </UDashboardToolbar>

      <NuxtPage />
    </UDashboardPanel>
  </UDashboardPage>
</template>
