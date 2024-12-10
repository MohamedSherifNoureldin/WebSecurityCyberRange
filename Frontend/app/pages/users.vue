<script lang="ts" setup>
const defaultColumns = [
  { key: 'user_id', label: '#' },
  { key: 'name', label: 'Name' },
  { key: 'email', label: 'Email' },
  { key: 'actions' }
]

const q = ref('')
const selectedColumns = ref(defaultColumns)
const modal = ref(false)
const input = ref<{ input: HTMLInputElement }>()
const users = ref([])
const apiURL = useRuntimeConfig().public.apiURL
const token = useCookie('token')
const columns = computed(() =>
  defaultColumns.filter(column => selectedColumns.value.includes(column))
)

definePageMeta({
  middleware: 'unauthorized',
  layout: 'dashboard'
})

const loading = ref(false)
const loadingAction = ref(false)
const errorMessageAction = ref('')
const toast = useToast();

async function getUsers () {
  loading.value = true
  const response = await fetch(`${apiURL}/api/v1/admin/get-users`, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token.value}`
    }
  })

  if (!response.ok) {
    console.error('Failed to fetch users', response)
    loading.value = false
    return
  }

  users.value = await response.json()
  loading.value = false
}

type User = {
  user_id: number
  name: string
  email: string
}

const deleteUser = async (email: string) => {
  loadingAction.value = true
  modal.value = true
  const response = await fetch(
    `${apiURL}/api/v1/admin/delete-user?email=` + email,
    {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token.value}`
      }
    }
  )

  if (!response.ok) {
    const data = await response.json()
    loadingAction.value = false

    toast.add({
      title:"Error",
      description: data.error,
      color:"red",
      icon:"i-heroicons-x-circle-20-solid"
    })

    return
  } else {
    toast.add({
      title:"Success",
      description: "User deleted successfully!",
      color:"green",
      icon:"i-heroicons-check-circle-20-solid"
    })

  }

  errorMessageAction.value = ''
  loadingAction.value = false
  await getUsers()
}

const makeAdmin = async (email: string) => {
  loadingAction.value = true
  const response = await fetch(
    `${apiURL}/api/v1/admin/make-admin?email=` + email,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token.value}`
      }
    }
  )

  if (!response.ok) {
    loadingAction.value = false
    const data = await response.json()
    toast.add({
      title:"Error",
      description: data.error,
      color:"red",
      icon:"i-heroicons-x-circle-20-solid"
    })

    return
  } else {
    toast.add({
      title:"Success",
      description: "User is now admin successfully!",
      color:"green",
      icon:"i-heroicons-check-circle-20-solid"
    })


  }

  errorMessageAction.value = ''
  loadingAction.value = false
  await getUsers()
}

const items = (row: User) => [
  [
    {
      label: 'Make Admin',
      icon: 'i-heroicons-key-20-solid',
      click: async () => {
        await makeAdmin(row.email)
        modal.value = true
      },
    },
  ],
  [
    {
      label: 'Delete User',
      icon: 'i-heroicons-trash-20-solid',
      click: async () => {
        await deleteUser(row.email)
        modal.value = true
      },
    },
  ],
]

const prepareModal = (type: 'makeAdmin' | 'deleteUser') => {
  const content = {
    makeAdmin: 'Are you sure you want to make this user admin? This action cannot be undone.',
    deleteUser: 'Are you sure you want to delete this user? This action cannot be undone.',
  }

  const actions = {
    makeAdmin,
    deleteUser,
  }
}

const filteredRows = computed(() => {
  return users.value.filter((user: User) => {
    return user.name.toLowerCase().includes(q.value.toLowerCase())
  })
})

defineShortcuts({
  '/': () => { input.value?.input?.focus() }
})

onMounted(async () => {
  await getUsers()
})
</script>

<template>
  <UDashboardPage>
    <UDashboardPanel grow>
      <UDashboardNavbar
        title="Users"
        :badge="users.length"
      >
        <template #right>
          <UInput
            ref="input"
            v-model="q"
            icon="i-heroicons-funnel"
            autocomplete="off"
            placeholder="Filter users..."
            class="hidden lg:block"
            @keydown.esc="$event.target.blur()"
          >
            <template #trailing>
              <UKbd value="/" />
            </template>
          </UInput>
        </template>
      </UDashboardNavbar>

      <UTable
        :loading-state="{
          icon: 'i-heroicons-arrow-path-20-solid',
          label: 'Loading...'
        }"
        :rows="filteredRows"
        :columns="columns"
        :loading="loading"
        sort-mode="manual"
        class="w-full"
        :ui="{ divide: 'divide-gray-200 dark:divide-gray-800' }"
      >
        <template #name-data="{ row }">
          <div class="flex items-center gap-3">
            <span class="font-medium text-gray-900 dark:text-white">{{
              row.name
            }}</span>
          </div>
        </template>

        <template #email-data="{ row }">
          <UBadge
            :label="row.email"
            color="green"
            variant="subtle"
          />
        </template>

        <template #actions-data="{ row }">
          <UDropdown :items="items(row)">
            <UButton
              color="gray"
              variant="ghost"
              icon="i-heroicons-ellipsis-horizontal-20-solid"
            />
          </UDropdown>
        </template>
      </UTable>
    </UDashboardPanel>

    <ModalUserActions :show-modal="modal" />
    <UNotifications/>
  </UDashboardPage>
</template>
