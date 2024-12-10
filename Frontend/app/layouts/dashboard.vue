<script setup lang="ts">
const { metaSymbol } = useShortcuts()
const { isDashboardSearchModalOpen } = useUIState()
const role = useCookie('role')
const toggleSearchModal = () => {
  isDashboardSearchModalOpen.value = true
}

const token = useCookie('token')
const apiURL = useRuntimeConfig().public.apiURL

const adminLinks = [
  {
    id: 'home',
    label: 'Home',
    icon: 'i-heroicons-home',
    to: '/dashboard',
    tooltip: {
      text: 'Home',
      shortcuts: ['G', 'H'],
    },
  },
  {
    id: 'labs',
    label: 'Labs',
    icon: 'i-heroicons-beaker',
    to: '/labs',
    tooltip: {
      text: 'Labs',
      shortcuts: ['G', 'L'],
    },
  },

  {
    id: 'ctf',
    label: 'CTF',
    icon: 'i-heroicons-trophy',
    defaultOpen: false,
    children: [
      {
        label: 'Scoreboard',
        to: '/ctf/scoreboard',
      },
      {
        label: 'Setup',
        to: '/ctf/setup',
      },
    ],
    to: '/ctf/jeopardy',
    tooltip: {
      text: 'CTF',
      shortcuts: ['G', 'C'],
    },
  },
  {
    id: 'users',
    label: 'Users',
    icon: 'i-heroicons-user-group',
    to: '/users',
    tooltip: {
      text: 'Users',
      shortcuts: ['G', 'U'],
    },
  },
]

const userLinks = [
  {
    id: 'home',
    label: 'Home',
    icon: 'i-heroicons-home',
    to: '/dashboard',
    tooltip: {
      text: 'Home',
      shortcuts: ['G', 'H'],
    },
  },
  {
    id: 'labs',
    label: 'Labs',
    icon: 'i-heroicons-beaker',
    to: '/labs',
    tooltip: {
      text: 'Labs',
      shortcuts: ['G', 'L'],
    },
  },

  {
    id: 'ctf',
    label: 'CTF',
    icon: 'i-heroicons-trophy',
    children: [
      {
        label: 'Jeopardy',
        to: '/ctf/jeopardy',
        exact: true,
      },
      {
        label: 'Scoreboard',
        to: '/ctf/scoreboard',
      },
    ],
    to: '/ctf',
    tooltip: {
      text: 'CTF',
      shortcuts: ['G', 'C'],
    },
  },
]
const links = role.value === 'admin' ? adminLinks : userLinks

const groups = [
  {
    key: 'links',
    label: 'Go to',
    commands: links.map(link => ({
      ...link,
      shortcuts: link.tooltip?.shortcuts,
    })),
  },
]

function navigate() {
  navigateTo('/dashboard')
}
</script>

<template>
  <UDashboardLayout>
    <UDashboardPanel
      :width="250"
      :resizable="{ min: 200, max: 300 }"
      collapsible
    >
      <UDashboardNavbar
        class="!border-transparent"
        :ui="{ left: 'flex-1' }"
      >
        <template #left>
          <Icon
            icon="AUC"
            class="h-44 max-w-44 hover:cursor-pointer"
            @click="navigate"
          />
        </template>
      </UDashboardNavbar>

      <UDashboardSidebar>
        <template #header />

        <UDashboardSidebarLinks :links="links" />

        <UDivider />

        <div class="flex-1" />

        <div class="flex w-full flex-row items-center justify-between">
          <div class="flex">
            <ColorPicker />
            <UColorModeButton />
          </div>
          <div
            class="focus-visible:ring-primary-500 dark:focus-visible:ring-primary-400 hover: flex shrink-0 cursor-pointer items-center gap-x-1 space-x-1 rounded-md p-1.5 font-medium text-gray-700 hover:bg-gray-50 hover:text-gray-900 focus:outline-none focus-visible:outline-0 focus-visible:ring-2 focus-visible:ring-inset disabled:cursor-not-allowed disabled:opacity-75 dark:text-gray-200 dark:hover:bg-gray-800 dark:hover:text-white"
            @click="toggleSearchModal"
          >
            <UIcon name="i-heroicons-magnifying-glass" />
            <UKbd value="K" />
            <UKbd :value="metaSymbol" />
          </div>
        </div>

        <UDivider class="sticky bottom-0" />

        <template #footer>
          <NavigationUserDropdown />
        </template>
      </UDashboardSidebar>
    </UDashboardPanel>

    <slot />

    <NavigationHelpSlideover />

    <ClientOnly>
      <LazyUDashboardSearch :groups="groups" />
    </ClientOnly>
  </UDashboardLayout>
</template>
