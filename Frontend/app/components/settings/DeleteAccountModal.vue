<script setup lang="ts">
const model = defineModel({
  type: Boolean
})

const toast = useToast()
const loading = ref(false)
const apiURL = useRuntimeConfig().public.apiURL
const role = useCookie('role')
const token = useCookie('token')
const name = useCookie('name')

async function onDelete () {
  loading.value = true
  const response = await fetch(`${apiURL}/api/v1/shared/delete-account`, {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token.value}`,
    },
    method: 'DELETE',
  })

  const data = await response.json()

  if (!response.ok) {
    loading.value = false
    return toast.add({
      title: 'Failed to delete account',
      description:  data.error,
      color: 'red',
      icon: 'i-heroicons-x-circle-20-solid'
    })
  }

  loading.value = false
  toast.add({
    title: 'Account deleted',
    icon: 'i-heroicons-check-circle-20-solid',
    color: 'green'
  })

  role.value = ''
  token.value = ''
  name.value = ''
  navigateTo('/loginpagetocyberrange')

  model.value = false
}
</script>

<template>
  <UDashboardModal
    v-model="model"
    title="Delete account"
    description="Are you sure you want to delete your account?"
    icon="i-heroicons-exclamation-circle"
    prevent-close
    :close-button="null"
    :ui="{
      icon: {
        base: 'text-red-500 dark:text-red-400'
      } as any,
      footer: {
        base: 'ml-16'
      } as any
    }"
  >
    <template #footer>
      <UButton
        color="red"
        label="Delete"
        :loading="loading"
        @click="onDelete"
      />
      <UButton
        color="white"
        label="Cancel"
        @click="model = false"
      />
    </template>
  </UDashboardModal>
</template>
