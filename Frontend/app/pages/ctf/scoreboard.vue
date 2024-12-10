<script setup lang="ts">
const loading = ref(false)
const logger = useLogger('API')
const apiURL = useRuntimeConfig().public.apiURL
const token = useCookie('token')
const scoreboard = ref([])
const release_date = ref('')
const diff = ref(0)
const message = ref('')
const name = useCookie('name')
const userindex = ref(0)

const columns = [
  {
    key: 'rank',
    label: 'Rank',
  },
  {
    key: 'name',
    label: 'Name',
  },
  {
    key: 'score',
    label: 'Score',
    direction: 'desc' as const,
  },
]

definePageMeta({
  layout: 'dashboard',
})

async function getScoreboard () {
  loading.value = true

  const response = await fetch(`${apiURL}/api/v1/shared/get-scoreboard`, {
    headers: {
      Authorization: `Bearer ${token.value}`,
    },
  })

  const data = await response.json()
  await nextTick()
  if (!response.ok) {
    loading.value = false
    return alert('Failed to fetch Challenges')
  } else {
    if (data.scoreboard && data.scoreboard.length > 0) {
      scoreboard.value = data.scoreboard
      userindex.value = data.userindex
    } else {
      scoreboard.value = []
    }

    if (data.message) {
      message.value = data.message
    }

    if (data.release_date) {
      release_date.value = data.release_date
      const now = new Date()
      const releaseDate = new Date(release_date.value)
      diff.value = releaseDate.getTime() - now.getTime()
    }

    if (data.message) {
      message.value = data.message
    }
  }

  loading.value = false
  return
}
onMounted(() => {
  getScoreboard()
})
</script>

<template>
  <UDashboardPage>
    <UDashboardPanel grow>
      <UDashboardNavbar title="Scoreboard" />

      <UDashboardPanelContent>
        <div v-if="!message && !release_date" class="p-4">
          <UTable
            :loading="loading"
            :loading-state="{
              icon: 'i-heroicons-arrow-path-20-solid',
              label: 'Loading...'
            }"
            :progress="{ color: 'primary', animation: 'elastic' }"
            :columns="columns"
            :rows="scoreboard"
            :empty-state="{
              icon: 'i-heroicons-circle-stack-20-solid',
              label: 'No Data Yet.'
            }"
          >
            <template #name-data="{ row }">
              <div
                v-if="row == scoreboard[userindex]"
                class="flex items-center"
              >
                <span class="text-primary-500 dark:text-primary-400" v-html="row.name"/>

                 <span
                  class="ml-2 px-2 py-1 text-xs font-semibold text-white bg-primary-500 dark:bg-primary-400 rounded-full"
                >
                  You
                </span>
              </div>
              <div
                v-else
                class="flex items-center"
              >
                <span v-html="row.name"/>

              </div>
            </template>
          </UTable>
        </div>

        <div
          v-if="message != ''"
          class="flex justify-center items-center p-4"
        >
          <ULandingSection
            :title="message"
            description="While you're waiting, why not dive into the labs? 🧪"
          />
        </div>

        <div
          v-if="release_date != ''"
          class="flex justify-center items-center p-4"
        >
          <div
            class="flex flex-col justify-center items-center p-3 rounded-lg"
          >
            <p>The CTF will start in:</p>
            <br>

            <Countdown
              v-slot="{ days, hours, minutes, seconds }"
              :time="diff"
            >
              <div class="text-center">
                <p
                  class="font-extrabold text-8xl text-black dark:text-white transition-transform animate-pulse cursor-pointer hover:scale-105"
                >
                  {{ days }}d : {{ hours }}h : {{ minutes }}m
                  : {{ seconds }}s 🚀
                </p>
              </div>
            </Countdown>
          </div>
        </div>
      </UDashboardPanelContent>
    </UDashboardPanel>
  </UDashboardPage>
</template>
