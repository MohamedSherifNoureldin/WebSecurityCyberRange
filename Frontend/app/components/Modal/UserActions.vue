<template>
  <UModal
    v-if="showModal"
    class="p-6"
    @close="modal = false"
  >
    <UCard :ui="{ ring: '', divide: 'divide-y divide-gray-100 dark:divide-gray-800' }">
      <template #header>
        <div class="flex items-center justify-between">
          <h3
            class="text-base font-semibold leading-6 text-gray-900 dark:text-white"
          >
            Confirmation
          </h3>
          <UButton
            color="gray"
            variant="ghost"
            icon="i-heroicons-x-mark-20-solid"
            class="-my-1"
            @click="modal = false"
          />
        </div>
      </template>

      <div class="p-4">
        <p class="text-sm text-gray-600 dark:text-gray-400">
          {{ modalTitle }}
        </p>
        <div class="mt-4 flex justify-end space-x-2">
          <UButton
            color="gray"
            @click="modal = false"
          >
            Cancel
          </UButton>
          <UButton
            color="primary"
            :loading="loadingAction"
            @click="modalAction"
          >
            Confirm
          </UButton>
        </div>
        <UAlert
          v-if="errorMessageAction"
          color="red"
          icon="i-heroicons-information-circle-20-solid"
          :title="errorMessageAction"
          class="mt-4"
        />
      </div>
    </UCard>
  </UModal>
</template>

<script lang="ts" setup>
const modal = ref(false)
const modalTitle = ref('')
const loadingAction = ref(false)
const errorMessageAction = ref('')
const modalAction = () => {
}

const props = defineProps({
  showModal: {
    type: Boolean,
    default: false
  },
})
</script>
