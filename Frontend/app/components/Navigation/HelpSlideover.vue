<script setup lang="ts">
const { isHelpSlideoverOpen } = useDashboard()
const feedback = ref('')
const type = ref('')
const apiURL = useRuntimeConfig().public.apiURL
const token = useCookie('token')
const toast = useToast()
const types = ['Issue', 'Compliment', 'Suggestion', 'Other']
const selectedType = ref(types[2])

async function submitFeedback() {
  if (feedback.value.length === 0) {
    return toast.add({
      title: 'Failed to submit feedback',
      description: 'Feedback cannot be empty.',
      color: 'red',
    })
  }

  if (feedback.value.length > 100) {
    return toast.add({
      title: 'Failed to submit feedback',
      description: 'Feedback cannot be longer than 100 characters.',
      color: 'red',
    })
  }

  const response = await fetch(`${apiURL}/api/v1/user/feedback`, {
    headers: {
      'Authorization': `Bearer ${token.value}`,
      'Content-Type': 'application/json',
    },
    method: 'POST',
    body: JSON.stringify({
      feedback: feedback.value,
      type: selectedType.value,
    }),
  })

  const data = await response.json()

  if (!response.ok) {
    return toast.add({
      title: 'Failed to submit feedback',
      description: data.error,
      color: 'red',
    })
  } else {
    feedback.value = ''
    toast.add({
      title: 'Feedback submitted',
      description: 'Thank you for your feedback.',
      color: 'green',
    })

    isHelpSlideoverOpen.value = false
  }
}
</script>

<template>
  <UDashboardModal v-model="isHelpSlideoverOpen">
    <template #header>
      <div class="flex items-center space-x-2">
        <!-- <UHeroicon name="question-mark-circle" /> -->
        <h2 class="text-lg font-semibold">
          Feedback
        </h2>
      </div>
    </template>

    <div class="p-4">
      <label class="block text-sm font-semibold">Message</label>

      <UTextarea
        v-model="feedback"
        placeholder="Please, feel free to share your feedback with us."
        class="w-full"
        :rows="10"
      />

      <label class="mt-4 block text-sm font-semibold">Type</label>

      <USelectMenu v-model="selectedType" :options="types" class="mt-1" />

      <div class="mt-4 flex justify-end space-x-2">
        <UButton color="gray" @click="isHelpSlideoverOpen = false">
          Cancel
        </UButton>
        <UButton color="primary" @click="submitFeedback">
          Submit
        </UButton>
      </div>

      </div>
  </UDashboardModal>
</template>
