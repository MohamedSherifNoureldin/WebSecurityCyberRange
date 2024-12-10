<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { addDays, format } from 'date-fns'

definePageMeta({
  middleware: 'unauthorized',
})

const toast = useToast()
const flag = ref('')
const logger = useLogger('API')
const ctfStatus = ref(false)
const releaseDate = ref(new Date().toDateString())
const loading = ref(false)
const loadingSave = ref(false)
const settingsChanged = ref(false)

const apiURL = useRuntimeConfig().public.apiURL
const token = useCookie('token')
const isSetforRelease = ref(false)
const now = ref(format(new Date(), 'yyyy-MM-dd\'T\'HH:mm'));


const initialSettings = ref({
  flag: '',
  ctfStatus: false,
  isSetforRelease: false,
  releaseDate: new Date().toDateString(),
})

async function getSettings () {
  loading.value = true
  const response = await fetch(`${apiURL}/api/v1/admin/get-settings?type=jeopardy`, {
    headers: {
      Authorization: `Bearer ${token.value}`,
    },
  })

  const data = await response.json()
  flag.value = data.flag
  if (data.status === 'true') {
    ctfStatus.value = true
  }

  if (data.set_for_release === 'true') {
    isSetforRelease.value = true
    releaseDate.value = data.release_date
  }

  initialSettings.value = {
    flag: data.flag,
    ctfStatus: data.status === 'true',
    isSetforRelease: data.set_for_release === 'true',
    releaseDate: data.release_date,
  }

  loading.value = false
}

async function saveSettings () {
  loadingSave.value = true
  const response = await fetch(
        `${apiURL}/api/v1/admin/save-settings?flag=${flag.value}&status=${ctfStatus.value}&set_for_release=${isSetforRelease.value}&release_date=${releaseDate.value}&type=jeopardy`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${token.value}`,
          },
        },
  )

  const data = await response.json()

  loadingSave.value = false
  settingsChanged.value = false
  toast.add({
    title: 'Settings saved',
    icon: 'i-heroicons-check-circle',
    color: 'green',
  })
  getSettings()
}

onMounted(() => {
  getSettings()
})

watch([flag, ctfStatus, isSetforRelease, releaseDate], () => {
  settingsChanged.value
        = flag.value !== initialSettings.value.flag
        || ctfStatus.value !== initialSettings.value.ctfStatus
        || isSetforRelease.value !== initialSettings.value.isSetforRelease
        || releaseDate.value !== initialSettings.value.releaseDate
})
</script>

<template>
  <UDashboardPanelContent class="-mt-12">
    <UDashboardSection>
      <UFormGroup
        name="flag"
        label="Default Flag Format"
        description="The default flag format for challenges."
        required
        class="items-center gap-2 grid grid-cols-2"
        :ui="{ container: '' }"
      >
        <UInput
          v-model="flag"
          autocomplete="off"
          icon="i-heroicons-user"
          size="md"
          placeholder="AUCYBERCTF{flag}"
        />
      </UFormGroup>
      <UFormGroup
        name="ctfStatus"
        label="CTF Status"
        description="Make the CTF live now."
        required
        class="items-center gap-2 grid grid-cols-2"
        :ui="{ container: '' }"
      >
        <div class="flex justify-end">
          <UToggle
            v-model="ctfStatus"
            on-icon="i-heroicons-check-20-solid"
            off-icon="i-heroicons-x-mark-20-solid"
            size="lg"
            :disabled="isSetforRelease"
          />
        </div>
      </UFormGroup>

      <UFormGroup
        name="releaseTime"
        label="Set Release Date"
        description="Set a Timer for the CTF to go live."
        required
        class="items-center gap-2 grid grid-cols-2"
        :ui="{ container: '' }"
      >
        <div class="flex justify-end items-center">
          <UToggle
            v-model="isSetforRelease"
            on-icon="i-heroicons-check-20-solid"
            off-icon="i-heroicons-x-mark-20-solid"
            size="lg"
            :disabled="ctfStatus"
          />

          <UInput
            v-if="isSetforRelease"
            v-model="releaseDate"
            size="lg"
            class="ml-2"
            placeholder="Release Date"
            type="datetime-local"
            :min="now"
          />
        </div>
      </UFormGroup>
    </UDashboardSection>

    <UDivider class="mb-4" />

    <UDashboardSection>
      <template #links>
        <UButton
          :loading="loadingSave"
          :disabled="!settingsChanged"
          icon="i-heroicons-check"
          type="submit"
          label="Save changes"
          color="black"
          @click="saveSettings"
        />
      </template>
    </UDashboardSection>
  </UDashboardPanelContent>
</template>
