<!-- eslint-disable vuejs-accessibility/mouse-events-have-key-events -->
<!-- eslint-disable-next-line vuejs-accessibility/mouse-events-have-key-events -->
<!-- eslint-disable vuejs-accessibility/no-static-element-interactions -->
 <!-- eslint-disable vuejs-accessibility/click-events-have-key-events -->
<template>
  <div
    :id="`terminal${index}`"
    ref="container"
    class="m-0 focus:m-3 overflow-hidden size-full"
    :tabindex="activeIndex === index ? -1 : 0"
    @dragover.prevent
    @dragenter="dragEnter"
    @dragleave="dragLeave"
    @drop="release"
  >
    <div
      v-if="dragging"
      class="top-0 left-0 z-[1] box-border absolute flex flex-col justify-center items-center bg-black/70 p-5 rounded-lg duration-300 ease-in-out size-full"
    >
      <UIcon name="i-heroicons-arrow-up-on-square-stack" class="mb-2 text-white size-10" />
      <div class="text-lg text-white">
        Drop files to upload
      </div>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { Xterm } from './index'

const container = ref()
const modal = ref(false)
const dragging = ref(false)

const props = defineProps({
  wsUrl: { type: String, required: true },
  tokenUrl: { type: String, required: false },
  clientOptions: { type: Object },
  termOptions: { type: Object },
  flowControl: { type: Object },
  activeIndex: { type: Number },
  index: { type: Number },
})

let xterm: Xterm

function showModal() { modal.value = true }
function dragEnter() { dragging.value = true }
function dragLeave() { dragging.value = false }
function release() { dragging.value = false }

function focusTerminal() {
  if (import.meta.client) {
    if (props.activeIndex === props.index) {
      const contain = container.value
      const textarea = contain?.querySelector('textarea')
      if (textarea) {
        textarea.focus()
      }
    }
  }
}

onMounted(() => {
  // @ts-expect-error
  xterm = new Xterm({ ...props }, showModal)
  if (container.value) {
    xterm.open(container.value)
    xterm.connect()
  } else {
    console.error('Container element is null')
  }

  if (import.meta.client) {
    focusTerminal()
  }
})

watch(() => props.activeIndex, async (newIndex) => {
  await nextTick()
  focusTerminal()
})

onBeforeUnmount(() => {
  xterm.dispose()
})
</script>

<style scoped>
@import "@xterm/xterm/css/xterm.css";
</style>
