<script setup lang="ts">
const { isHelpSlideoverOpen } = useDashboard()
const role = useCookie('role')
const token = useCookie('token')
const name = useCookie('name')

const userItems = computed(() => [
  [
    {
      slot: 'account',
      label: '',
      disabled: true,
    },
  ],

  [
    {
      label: 'Settings',
      icon: 'i-heroicons-cog-8-tooth',
      to: '/settings',
    },

    {
      label: 'Feedback',
      icon: 'i-heroicons-chat-bubble-left-ellipsis',
      click: () => (isHelpSlideoverOpen.value = true),
    },
  ],
  [
    {
      label: '',
      to: 'https://canvas.aucegypt.edu',
      target: '_blank',
      icon: 'i-heroicons-academic-cap',
      external: true,
      slot: 'BB',
    },
  ],
  [
    {
      label: 'Sign out',
      icon: 'i-heroicons-arrow-left-on-rectangle',
      click: () => {
        role.value = ''
        token.value = ''
        name.value = ''
        navigateTo('/loginpagetocyberrange')
      },
    },
  ],
])

const adminItems = computed(() => [
  [
    {
      slot: 'account',
      label: '',
      disabled: true,
    },
  ],
  [
    {
      label: 'Settings',
      icon: 'i-heroicons-cog-8-tooth',
      to: '/settings',
    },
    {
      label: 'Feedback',
      icon: 'i-heroicons-chat-bubble-left-ellipsis',
      to: '/feedback',
    },
  ],
  [
    {
      label: '',
      to: 'https://canvas.aucegypt.edu',
      target: '_blank',
      icon: 'i-heroicons-academic-cap',
      external: true,
      slot: 'BB',
    },
  ],
  [
    {
      label: 'Sign out',
      icon: 'i-heroicons-arrow-left-on-rectangle',
      click: () => {
        role.value = ''
        token.value = ''
        name.value = ''
        navigateTo('/loginpagetocyberrange')
      },
    },
  ],
])

const items = computed(() =>
  role.value === 'admin' ? adminItems.value : userItems.value,
)
</script>

<template>
  <UDropdown
    mode="hover"
    :items="items"
    :ui="{ width: 'w-full', item: { disabled: 'cursor-text select-text' } }"
    :popper="{ strategy: 'absolute', placement: 'top' }"
    class="w-full"
  >
    <template #default="{ open }">
      <UButton
        color="gray"
        variant="ghost"
        class="w-full"
        :label="name as string"
        :class="[open && 'bg-gray-50 dark:bg-gray-800']"
      >
        <template #trailing>
          <UIcon
            name="i-heroicons-ellipsis-vertical"
            class="ml-auto size-5"
          />
        </template>
        </UButton>
    </template>

    <template #account>
      <div class="text-left">
        <p>Signed in as</p>

        <p class="font-medium text-gray-900 dark:text-white">
          {{ name }}
        </p>
      </div>
    </template>

    <template #BB>
      <div class="flex items-center">
        <UIcon name="i-heroicons-academic-cap" class="mr-2 size-5" />
        <p class="font-medium text-gray-900 dark:text-white">
          AUC Canvas
        </p>
      </div>
      <UIcon
        name="i-heroicons-arrow-top-right-on-square"
        class="ml-auto size-5"
      />
    </template>
  </UDropdown>
</template>
