<template>
  <div>
    <UCard class="w-full max-w-sm bg-white/75 backdrop-blur dark:bg-white/5">
      <Icon icon="AUC" class="size-auto" />
      <UAuthForm
        :fields="fields"
        :validate="validate"
        title="Welcome back 👋"
        align="top"
        :ui="{ base: 'text-center', footer: 'text-center' }"
        :submit-button="{
          label: 'Login',
          trailingIcon: 'i-heroicons-arrow-right-20-solid'
        }"
        :loading="loading"
        class="mt-5"
        @submit="onSubmit"
      >
        <template #description />

        <template #password-hint>
                <NuxtLink to="/forgetpasswordman" class="text-primary font-medium">Forgot password?</NuxtLink>
              </template>

        <template v-if="errorMessage" #validation>
          <UAlert
            color="red"
            icon="i-heroicons-information-circle-20-solid"
            :title="errorMessage"
          />
        </template>

        <template #footer>
          Don't have an account?
          <NuxtLink
            to="/noaccount"
            class="text-primary font-medium"
          >Sign up</NuxtLink>.
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
  </div>
</template>

<script setup lang="ts">
const apiURL = useRuntimeConfig().public.apiURL

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
    name: 'email_or_id',
    type: 'text',
    label: 'Email or ID',
    placeholder: 'john.doe@aucegypt.edu',
  },
  {
    name: 'password',
    label: 'Password',
    type: 'password',
    placeholder: 'password',
  },
]

const validate = (state: any) => {
  const errors = []
  if (!state.email_or_id) { errors.push({ path: 'email_or_id', message: 'Email or ID is required' }) }
  if (!state.password) { errors.push({ path: 'password', message: 'Password is required' }) }
  return errors
}

function onSubmit(data: any) {
  loading.value = true
  fetch(`${apiURL}/api/v1/auth/login`, {
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
        token.value = res.token
        role.value = res.role
        name.value = res.name

        navigateTo('/dashboard')
      }
    })
    .catch((error) => {
      loading.value = false
      errorMessage.value = 'Network error, please try again later.'
    })
}
</script>
