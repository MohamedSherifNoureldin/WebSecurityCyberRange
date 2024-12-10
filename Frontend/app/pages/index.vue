
<template>

  <div class="flex flex-col items-center min-h-screen">
  <Icon icon="AUC" class="size-32 -mb-20" />

  <ULandingHero
      class="text-center py-16 px-4  rounded-lg max-w-4xl"
      title="AUC Cyberrange"
      description="Advance your cybersecurity skills with cutting-edge labs, hands-on challenges, and real-world scenarios."
    >
    <template #headline>
        <p class="text-lg font-semibold  mt-4">
          Join the future of cybersecurity training and competitions
        </p>
      </template>

      <UDivider/>
    </ULandingHero>

    <section class="py-16 w-full">
      <div class="container mx-auto text-center">
        <h2 class="text-2xl font-bold mb-12">
          Why Choose AUC Cyberrange?
        </h2>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-8 border">

        <div class="p-6   rounded-lg shadow-md">
            <h3 class="text-xl font-semibold mb-4  ">Hands-on Labs</h3>
            <p >
              Practice cybersecurity skills with immersive, real-world labs and challenges.
            </p>
          </div>

          <div class="p-6   rounded-lg shadow-md">
            <h3 class="text-xl font-semibold mb-4">Capture the Flag Competitions</h3>
            <p>
              Participate in CTFs designed to enhance your knowledge and test your skills.
            </p>
          </div>

          <div class="p-6  rounded-lg shadow-md">
            <h3 class="text-xl font-semibold mb-4">Expert Mentorship</h3>
            <p>
              Learn from top cybersecurity experts and receive personalized guidance.
            </p>
          </div>
        </div>
      </div>

    </section>


    <div class="container mx-auto text-center mb-10">
      <UButton label="Send Us Message!" class="neon-button" @click="isHelpSlideoverOpen = true"/>
    </div>


    <UDashboardModal v-model="isHelpSlideoverOpen">
      <template #header>
        <div class="flex items-center space-x-2">
           <h2 class="text-lg font-semibold">
            Feedback
          </h2>
        </div>
      </template>

      <div class="px-4">
      <label class="block text-sm font-semibold">Name</label>

          <UInput
            v-model="name"
            placeholder="Your Name"
            class="w-full"
          />

          <label class="mt-4 block text-sm font-semibold">Email</label>

            <UInput
              v-model="email"
              placeholder="Your Name"
              class="w-full"
              type="email"
            />

        <label class="mt-4 block text-sm font-semibold">Message</label>

        <UTextarea
          v-model="message"
          placeholder="Why are you contacting us?"
          class="w-full"
          :rows="10"
        />

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

    <UNotifications/>
  </div>
</template>


<script lang="ts" setup>
const message = ref('')
const apiURL = useRuntimeConfig().public.apiURL
const token = useCookie('token')
const toast = useToast()
const isHelpSlideoverOpen = ref(false)
const email = ref('')
const name = ref('')

async function submitFeedback() {
  if (!email.value || !name.value || !message.value) {
    return toast.add({
      title: 'Failed to submit feedback',
      description: 'Please fill in all fields.',
      color: 'red',
    })
  }


  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  if (!emailRegex.test(email.value)) {
    return toast.add({
      title: 'Failed to submit feedback',
      description: 'Please enter a valid email address.',
      color: 'red',
    })
  }

  const response = await fetch(`${apiURL}/api/v1/contact-us`, {
    headers: {
       'Content-Type': 'application/json',
    },
    method: 'POST',
    body: JSON.stringify({
      message: message.value,
      email: email.value,
      name: name.value,
    }),
  })

  const data = await response.json()

  if (!response.ok) {
    return toast.add({
      title: 'Failed to send message',
      description: data.error,
      color: 'red',
    })
  } else {
    toast.add({
      title: 'Message submitted',
      description: 'Thank you for your message! We will get back to you soon',
      color: 'green',
    })

    isHelpSlideoverOpen.value = false
  }
}

</script>


<style scoped>
.neon-button {
  font-size: 1rem;
  padding: 2px 5px;
   border: 2px solid #00ffcc;
  border-radius: 2px;
   text-transform: uppercase;
  letter-spacing: 2px;
  cursor: pointer;
  position: relative;
  transition: 0.4s;
  }

.neon-button:hover {

  box-shadow: 0 0 20px #00ffcc, 0 0 30px #00ffcc, 0 0 40px #00ffcc, 0 0 50px #00ffcc;
}

.neon-button:active {
  transform: scale(0.95);
}

</style>
