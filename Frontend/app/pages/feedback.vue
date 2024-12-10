<script setup lang="ts">
const feedbacks = ref<Feedback[]>([])
const toast = useToast()
const apiURL = useRuntimeConfig().public.apiURL
const token = useCookie('token')
type Feedback = {
  id: number
  feedback: string
  name: string
  created_at: string
  type: string
}

definePageMeta({
  layout: 'dashboard',
})

async function getFeedbacks () {
  const response = await fetch(`${apiURL}/api/v1/admin/feedback`, {
    headers: {
      'Authorization': `Bearer ${token.value}`,
      'Content-Type': 'application/json',
    },
    method: 'GET',
  })
  if (!response.ok) {
    return toast.add({
      title: 'Failed to fetch feedbacks',
      description: 'Please try again later.',
      color: 'red',
    })
  } else {
    const data = await response.json()
    feedbacks.value = data.feedbacks
  }
}
onMounted(() => {
  getFeedbacks()
})
</script>

<template>
  <UDashboardPage>
    <UDashboardPanel grow>
      <UDashboardNavbar title="Feedback" />

      <UDashboardPanelContent>
        <div class="flex flex-col space-y-4">
          <div class="flex flex-col space-y-4">
            <template v-for="feedback in feedbacks" :key="feedback.id">
              <div class="flex flex-col space-y-2">
                <div class="flex justify-between">
                  <p class="text-2xl font-bold">
                    {{ feedback.name }}
                    <UBadge
                      v-if="feedback.type == 'Issue'"
                      color="red"
                      variant="soft"
                      :label="feedback.type"
                    />

                    <UBadge
                      v-if="feedback.type == 'Compliment'"
                      color="green"
                      variant="soft"
                      :label="feedback.type"
                    />

                    <UBadge
                      v-if="feedback.type == 'Suggestion'"
                      color="violet"
                      variant="soft"
                      :label="feedback.type"
                    />

                    <UBadge
                      v-if="feedback.type == 'Other'"
                      color="lime"
                      variant="soft"
                      :label="feedback.type"
                    />
                  </p>
                  <p class="text-sm text-gray-500">
                    {{ feedback.created_at }}
                  </p>
                </div>
                <p class="text-xl" v-html="feedback.feedback"></p>

              </div>
              <UDivider />
            </template>
          </div>
        </div>
      </UDashboardPanelContent>
    </UDashboardPanel>
  </UDashboardPage>
</template>
