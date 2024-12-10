<!-- eslint-disable vuejs-accessibility/mouse-events-have-key-events -->
<!-- eslint-disable-next-line vuejs-accessibility/mouse-events-have-key-events -->
<!-- eslint-disable vuejs-accessibility/no-static-element-interactions -->
<!-- eslint-disable vuejs-accessibility/click-events-have-key-events -->

<template>
  <div class="flex h-screen flex-col">
    <!-- First part: Tabs -->
    <div v-if="loading" class="flex h-full flex-col items-center justify-center space-y-4 text-center">
      <Icon icon="Spinner" class="w-32" />
      <div class="text-4xl">
        Hang tight you hacker...loading your lab🫡
      </div>
      <div v-if="fact" class="rounded-lg bg-gray-800 p-4 text-lg text-white">
        {{ fact }}
      </div>
    </div>

    <div v-if="!loading && isWeb == 'false'" class="flex items-start">
      <div
        v-for="(item, index) in containerNamesArray"
        :key="index"
        class="cursor-pointer px-4 py-2 hover:underline"
        :class="{ underline: activeIndex === index }"
        @click=" activeIndex = index; triggerResize(); "
      >
        {{ item }}
      </div>
    </div>

    <!-- Second part: Terminal Container -->
    <div v-if="!loading && isWeb == 'false'" class="grow overflow-hidden">
      <div
        v-for="(item, index) in containerNamesArray"
        :key="index"
        class="flex size-full flex-col"
        :class="{ hidden: activeIndex !== index }"
      >
        <ClientOnly>
          <XtermTerminal
            :ws-url="`${wsURL}/api/v1/terminal?token=${token}&arg=${item}`"
            :flow-control="flowControl"
            :client-options="clientOptions"
            :term-options="termOptions"
            class="terminal size-full rounded-lg border-2 border-gray-300"
            :active-index="activeIndex"
            :index="index"
          />
        </ClientOnly>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeMount, onBeforeUnmount, ref } from 'vue'
import { useCookie, useRoute, useRuntimeConfig } from '#imports'

const wsURL = useRuntimeConfig().public.wsURL
const apiURL = useRuntimeConfig().public.apiURL
const serverURL = useRuntimeConfig().public.serverURL
const token = useCookie('token')
const container_names = useRoute().query.container_names

const labname = useRoute().query.labname
const loading = ref(true)
const fact = ref('')
const activeIndex = ref(0)
const isWeb = ref('false')
const port = ref('0')

const triggerResize = () => {
  setTimeout(() => {
    window.dispatchEvent(new Event('resize'))
  }, 10)

  // invoke tab stroke
}

const clientOptions = {
  rendererType: 'webgl',
  disableLeaveAlert: false,
  disableResizeOverlay: false,
  enableZmodem: true,
  titleFixed: labname,
  enableTrzsz: true,
  enableSixel: true,
  isWindows: false,
  unicodeVersion: '11',
}

const termOptions = {
  fontSize: 13,
  fontFamily: 'Consolas,Liberation Mono,Menlo,Courier,monospace',
  theme: {
    foreground: '#d2d2d2',
    background: '#2b2b2b',
    cursor: '#adadad',
    black: '#000000',
    red: '#d81e00',
    green: '#5ea702',
    yellow: '#cfae00',
    blue: '#427ab3',
    magenta: '#89658e',
    cyan: '#00a7aa',
    white: '#dbded8',
    brightBlack: '#686a66',
    brightRed: '#f54235',
    brightGreen: '#99e343',
    brightYellow: '#fdeb61',
    brightBlue: '#84b0d8',
    brightMagenta: '#bc94b7',
    brightCyan: '#37e6e8',
    brightWhite: '#f1f1f0',
  },
  allowProposedApi: true,
}

const flowControl = {
  limit: 100000,
  highWater: 10,
  lowWater: 4,
}

const containerNamesArray = computed(() => {
  return Array.isArray(container_names) ? container_names : [container_names]
})

async function runLab() {
  const response = await fetch(
        `${apiURL}/api/v1/shared/run-lab?name=` + labname,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${token.value}`,
          },
        },
  )

  const data = await response.json()
  isWeb.value = data.isWeb
  port.value = data.port
  if (!response.ok) {
    alert(data.error)
  }

  if (isWeb.value === 'true') {
    checkServerAndRedirect()
  } else {
    loading.value = false
  }

  loading.value = false
}

function checkServerAndRedirect() {
  window.location.href = `${serverURL}:${port.value}`
}

async function getFact() {
  await fetchAndDisplayFact()
  while (loading.value) {
    await new Promise(resolve => setTimeout(resolve, 8000))
    await fetchAndDisplayFact()
  }
}

async function fetchAndDisplayFact() {
  const response = await fetch(
    'https://uselessfacts.jsph.pl/api/v2/facts/random',
    {
      headers: {
        'Content-Type': 'application/json',
      },
    },
  )

  const data = await response.json()

  if (response.ok) {
    fact.value = data.text
  }
}

function handleKeyDown(event: KeyboardEvent) {
  if (event.ctrlKey && event.shiftKey && event.key.toLowerCase() === 's') {
    event.preventDefault()
    activeIndex.value = (activeIndex.value + 1) % containerNamesArray.value.length
    triggerResize()
  }
}

onBeforeMount(() => {
  getFact()
  runLab()
  window.addEventListener('keydown', handleKeyDown)
})

onBeforeUnmount(() => {
  window.removeEventListener('keydown', handleKeyDown)
})
</script>
