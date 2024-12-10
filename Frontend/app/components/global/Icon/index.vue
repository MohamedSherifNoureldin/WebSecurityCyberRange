<template>
  <component :is="`Icon${props.icon}`" />
</template>

<script lang="ts" setup>
const props = defineProps({
  icon: {
    type: String,
    required: true
  }
})
</script>
