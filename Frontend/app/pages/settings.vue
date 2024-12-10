<script setup lang="ts">
const isDeleteAccountModalOpen = ref(false)
const name = useCookie('name')
const toast = useToast()
const loading = ref(false)
const apiURL = useRuntimeConfig().public.apiURL
const token = useCookie('token')
const password_current = ref('')
const password_new = ref('')
const newName = ref('')

definePageMeta({
  layout: 'dashboard'
})

onMounted(() => {
  if (name.value && typeof name.value === 'string') {
    newName.value = name.value
  }
})

async function onSubmit () {
  loading.value = true

  if (password_new.value && password_new.value.length < 8) {
    toast.add({
      title: 'Password must be at least 8 characters long',
      color: 'red'
    })
    loading.value = false
    return
  }

  const response = await fetch(`${apiURL}/api/v1/shared/update-account`, {
    headers: {
      'Authorization': `Bearer ${token.value}`,
      'Content-Type': 'application/json',
    },
    method: 'PUT',
    body: JSON.stringify({
      name: newName.value,
      password_current: password_current.value,
      password_new: password_new.value,
    }),
  })

  const data = await response.json()

  if (!response.ok) {
    toast.add({
      title: data.error,
      description: 'Please try again later.',
      color: 'red'
    })

    loading.value = false
    return
  } else {
    toast.add({
      title: 'Profile updated',
      icon: 'i-heroicons-check-circle',
      color: 'green'
    })
    loading.value = false

    name.value = newName.value
  }
}
</script>

<template>
  <UDashboardPanel grow>
    <UDashboardNavbar title="Settings">
      <template #right />
    </UDashboardNavbar>
    <UDashboardPanelContent class="pb-24">
      <UDashboardSection>
        <UFormGroup
          name="name"
          label="Display Name"
          description="Will appear on the CTF scoreboard."
          required
          class="grid grid-cols-2 items-center gap-2"
          :ui="{ container: '' }"
        >
          <UInput
            v-model="newName"
            autocomplete="off"
            icon="i-heroicons-user"
            size="md"
          />
        </UFormGroup>

        <UFormGroup
          name="password"
          label="Password"
          description="Confirm your current password before setting a new one."
          class="grid grid-cols-2 gap-2"
          :ui="{ container: '' }"
        >
          <UInput
            id="password"
            v-model="password_current"
            type="password"
            placeholder="Current password"
            size="md"
          />
          <UInput
            id="password_new"
            v-model="password_new"
            type="password"
            placeholder="New password"
            size="md"
            class="mt-2"
          />
        </UFormGroup>
      </UDashboardSection>

      <UDashboardSection>
        <template #links>
          <UButton
            type="submit"
            label="Save changes"
            color="black"
            :loading="loading"
            @click="onSubmit"
          />
        </template>
      </UDashboardSection>

      <UDivider class="mb-4" />

      <UDashboardSection
        title="Account"
        description="No longer want to use our service? You can delete your account here. This action is not reversible. All information related to this account will be deleted permanently."
      >
        <div>
          <UButton
            color="red"
            label="Delete account"
            size="md"
            @click="isDeleteAccountModalOpen = true"
          />
        </div>
      </UDashboardSection>

      <SettingsDeleteAccountModal v-model="isDeleteAccountModalOpen" />
    </UDashboardPanelContent>
  </UDashboardPanel>
</template>
