<script setup lang="ts">
definePageMeta({
  middleware: 'in',
  layout: 'dashboard',
})

const role = useCookie('role')
const name = useCookie('name')
const logger = useLogger('API')
const apiURL = useRuntimeConfig().public.apiURL
const token = useCookie('token')
const ram = ref({})
const cpu = ref({})
const disk = ref({})
const loading = ref(false)
const toast = useToast()
const isLoggedOut = ref(false)

async function checkToken() {
  loading.value = true

  const response = await fetch(`${apiURL}/api/v1/shared/get-categories`, {
    headers: {
      Authorization: `Bearer ${token.value}`,
    },
  })

  if (response.status === 401) {
    isLoggedOut.value = true
    loading.value = false
    return
  }
}

async function getUsage() {
  loading.value = true

  const response = await fetch(`${apiURL}/api/v1/admin/usage`, {
    headers: {
      'Authorization': `Bearer ${token.value}`,
      'Content-Type': 'application/json',
    },
    method: 'GET',
  })

  const data = await response.json()
  if (!response.ok) {
    loading.value = false
    return
  } else {
    ram.value = data.memory
    cpu.value = data.cpu
    disk.value = data.disk
    loading.value = false
  }
}

async function Logout() {
  role.value = ''
  token.value = ''
  name.value = ''
  await navigateTo('/loginpagetocyberrange')
}

onMounted(() => {
  checkToken()
  if (role.value === 'admin') {
    getUsage()
  }
})
</script>

<template>
  <UDashboardPage>
    <UDashboardPanel grow>
      <UDashboardNavbar title="Home" />

      <UDashboardPanelContent>
        <ULandingHero
          v-if="role === 'user'"
          title="Cyber Range"
          description="Choose a lab and start hacking now!👨‍💻👩‍💻"
          :links="[
            {
              label: 'Get Started',
              icon: 'i-heroicons-rocket-launch',
              size: 'lg',
              to: '/labs'
            }
          ]"
        />

        <HomeCPU v-if="role === 'admin' && !loading" :data="cpu" />
        <HomeMemory v-if="role === 'admin' && !loading" :data="ram" class="mt-4" />
        <HomeDisk v-if="role === 'admin' && !loading" :data="disk" class="mt-4" />

        <UModal v-model="isLoggedOut" prevent-close>
          <UCard :ui="{ ring: '', divide: 'divide-y divide-gray-100 dark:divide-gray-800' }">
            <template #header>
              <div class="flex items-center justify-between">
                <h3 class="text-base font-semibold leading-6 text-gray-900 dark:text-white">
                  Token Expired
                </h3>
              </div>
            </template>

            <template #default>
              <div>
                <p>Your token has expired. You will be redirected to the login page.</p>
              </div>
            </template>
            <template #footer>
              <div class="flex justify-between">
                <UButton primary @click="Logout">
                  OK
                </UButton>
              </div>
            </template>
          </UCard>
        </UModal>
      </UDashboardPanelContent>
    </UDashboardPanel>
  </UDashboardPage>
</template>
