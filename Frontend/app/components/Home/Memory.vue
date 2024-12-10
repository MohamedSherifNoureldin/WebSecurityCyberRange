<template>
  <UDashboardCard title="Memory Usage" icon="i-heroicons-bolt">
    <div>
      <p>Total: {{ total }} GB</p>
      <p>Used: {{ used }} GB ({{ usedPercent }}%)</p>
      <p>Available: {{ available }} GB</p>
    </div>
  </UDashboardCard>
</template>

<script setup lang="ts">
const props = defineProps({
  data: {
    type: Object,
    required: true,
  },
})

const { data } = props

const toGB = (bytes: number) => (bytes / 1024 ** 3).toFixed(2)

const total = computed(() => toGB(data.total))
const used = computed(() => toGB(data.used))
const available = computed(() => toGB(data.available))
const usedPercent = computed(() => data.usedPercent)
</script>
