<template>
  <div>
    <UCard class="w-full max-w-sm bg-white/75 backdrop-blur dark:bg-white/5">
      <Icon icon="AUC" class="size-auto" />
      <UAuthForm
        v-if="!otpSent"
        :fields="fields"
        :validate="validate"
        title="Forget Password😢"
        align="top"
        :ui="{ base: 'text-center', footer: 'text-center' }"
        :submit-button="{
          label: 'Forget Password',
          trailingIcon: 'i-heroicons-arrow-right-20-solid'
        }"
        :loading="loading"
        class="mt-5"
        @submit="onSubmit"
      >
        <template #description />

        <template v-if="errorMessage" #validation>
          <UAlert
            color="red"
            icon="i-heroicons-information-circle-20-solid"
            :title="errorMessage"
          />
        </template>

        <template #footer>
        <NuxtLink
            to="/loginpagetocyberrange"
            class="text-primary font-medium"
          >        Login Instead
            </NuxtLink>.
        </template>
      </UAuthForm>

        <!-- when otp sent -->
        <UAuthForm
          v-if="otpSent"
          :fields="fieldsOtp"
          :validate="validateOtp"
          title="Forget Password😢"
          align="top"
          :ui="{ base: 'text-center', footer: 'text-center' }"
          :submit-button="{
            label: 'Forget Password',
            trailingIcon: 'i-heroicons-arrow-right-20-solid'
          }"
          :loading="loading"
          class="mt-5"
          @submit="onSubmitOtp"
        >
          <template #description />

          <template v-if="errorMessage" #validation>
            <UAlert
              color="red"
              icon="i-heroicons-information-circle-20-solid"
              :title="errorMessage"
            />
          </template>

          <template #footer>
          <NuxtLink
              to="/loginpagetocyberrange"
              class="text-primary font-medium"
            >        Login Instead
              </NuxtLink>.
          </template>
        </UAuthForm>


    </UCard>

    <div
      class="fixed inset-x-0 bottom-0 flex items-center justify-center p-4 text-center text-xs shadow"
      style="bottom: calc(100vh - 100%)"
    >
      <p class="mr-2 font-bold">
        Problems? Contact @
      </p>
      <NuxtLink to="mailto:aucyberange@gmail.com">
        <UBadge variant="subtle" class="text-primary rounded-full text-xs font-bold">
          <div class="px-2 py-0.5">
            aucyberange@gmail.com
          </div>
        </UBadge>
      </NuxtLink>
    </div>


    <UNotifications/>
  </div>
</template>

<script setup lang="ts">
const apiURL = useRuntimeConfig().public.apiURL
const otpSent = ref(false)
const toast = useToast()

const role = useCookie('role', {
  expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
})

const name = useCookie('name', {
  expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
})

const token = useCookie('token', {
  expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
})

const loading = ref(false)
const errorMessage = ref('')

definePageMeta({
  layout: 'auth',
})

const fields = [
  {
    name: 'email',
    type: 'text',
    label: 'Email',
    placeholder: 'john.doe@aucegypt.edu',
  }
]

const fieldsOtp = [
  {
    name: 'otp',
    type: 'text',
    label: 'OTP',
    placeholder: '123',
  },
  {
    name: 'password',
    type: 'password',
    label: 'Password',
    placeholder: '********',
  },
  {
    name: 'confirm_password',
    type: 'password',
    label: 'Confirm Password',
    placeholder: '********',
  }
]

const email = ref('')

const validate = (state: any) => {
  const errors = []
  if (!state.email) { errors.push({ path: 'email', message: 'Email is required' }) }
  return errors
}

const validateOtp = (state: any) => {
  const errors = []
  if (!state.otp) { errors.push({ path: 'otp', message: 'OTP is required' }) }
  if (!state.password) { errors.push({ path: 'password', message: 'Password is required' }) }
  if (!state.confirm_password) { errors.push({ path: 'confirm_password', message: 'Confirm Password is required' }) }
  //check if otp is less or more that 3 digits and also check if the password is less than 8 characters
  if (state.otp.length !== 3) { errors.push({ path: 'otp', message: 'OTP must be 3 digits' }) }
  if (state.password.length < 8) { errors.push({ path: 'password', message: 'Password must be at least 8 characters' }) }
  if (state.password !== state.confirm_password) { errors.push({ path: 'confirm_password', message: 'Passwords do not match' }) }


  return errors
}

function onSubmit(data: any) {
  loading.value = true
  fetch(`${apiURL}/api/v1/auth/forget-password`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(data),
  })
    .then(res => res.json())
    .then((res) => {
      loading.value = false
      if (res.error) {
        return (errorMessage.value = res.error)
      } else {
        email.value = data.email
        toast.add({ title: 'Check your email for OTP to reset your password', color: 'green' })
        otpSent.value = true
        //clear errors
        errorMessage.value = ''

      }
    })
    .catch((error) => {
      loading.value = false
      errorMessage.value = 'Network error, please try again later.'
    })
}

function onSubmitOtp(data: any) {
  //add email to data
  data.email =  email.value



  loading.value = true
  fetch(`${apiURL}/api/v1/auth/change-password`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(data),
  })
    .then(res => res.json())
    .then((res) => {
      loading.value = false
      if (res.error) {
        return (errorMessage.value = res.error)
      } else {
         toast.add({ title: 'Password changed successfully', color: 'green' })

         navigateTo('/loginpagetocyberrange')

      }
    })
    .catch((error) => {
      loading.value = false
      errorMessage.value = 'Network error, please try again later.'
    })
}
</script>
