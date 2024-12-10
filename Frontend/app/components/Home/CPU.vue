<script setup lang="ts">
const logger = useLogger('Props')
const props = defineProps({
  data: {
    type: Object,
    required: true,
  },
})

const { data } = props
</script>

<template>
  <UDashboardCard title="CPU Usage" icon="i-heroicons-cpu-chip">
    <div class="space-y-2">
      <UMeter
        v-for="(core, index) in data"
        :key="index"
        :value="core.value"
        :label="core.label"
        :color="core.color"
        size="lg"
        class="flex-row-reverse items-center"
        :ui="{
          label: { base: 'flex-shrink-0 w-24' },
          indicator: { container: '!w-auto' },
          meter: { base: 'flex-1' }
        }"
        indicator
      />
    </div>
  </UDashboardCard>
</template>
