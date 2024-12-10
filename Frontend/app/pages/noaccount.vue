<template>
  <div>
    <UCard class="w-full max-w-sm bg-white/75 backdrop-blur dark:bg-white/5">
      <Icon
        icon="AUC"
        class="size-auto"
      />

      <UAuthForm
        :fields="fields"
        :validate="validate"
        align="top"
        title="Create an account 🚀"
        :ui="{ base: 'text-center', footer: 'text-center' }"
        :submit-button="{ label: 'Create account' }"
        :loading="loading"
        class="mt-5"
        @submit="onSubmit"
      >
        <template
          v-if="errorMessage"
          #validation
        >
          <UAlert
            color="red"
            icon="i-heroicons-information-circle-20-solid"
            :title="errorMessage"
          />
        </template>


        <template #footer>
          Already have an account?
          <NuxtLink
            to="/loginpagetocyberrange"
            class="text-primary font-medium"
          >
            Login
          </NuxtLink>.
        </template>
      </UAuthForm>


    </UCard>
  </div>
</template>

<script setup lang="ts">
const apiURL = useRuntimeConfig().public.apiURL
const toast = useToast()
const loading = ref(false)
const errorMessage = ref('')

definePageMeta({
  layout: 'auth'
})

const fields = [
  {
    name: 'email',
    type: 'text',
    label: 'Email',
    placeholder: 'john.doe@aucegypt.edu'
  },
  {
    name: 'id',
    label: 'Student ID',
    type: 'text',
    placeholder: '90000'
  },
  {
    name: 'name',
    label: 'Display Name',
    type: 'text',
    placeholder: 'John'
  },
  {
    name: 'password',
    label: 'Password',
    type: 'password',
    placeholder: 'password'
  },
  {
    name: 'confirmPassword',
    label: 'Confirm Password',
    type: 'password',
    placeholder: 'confirm password'
  }
]

const validate = (state: any) => {
  const errors = []
  if (!state.email) { errors.push({ path: 'email', message: 'Email is required' }) }
  if (!state.id) { errors.push({ path: 'id', message: 'ID is required' }) }
  if (!state.name) { errors.push({ path: 'name', message: 'Display Name is required' }) }
  if (!state.password) { errors.push({ path: 'password', message: 'Password is required' }) }
  if (state.password !== state.confirmPassword) { errors.push({ path: 'confirmPassword', message: 'Passwords do not match' }) }

  return errors
}

function onSubmit (data: any) {
  loading.value = true
  fetch(`${apiURL}/api/v1/auth/register`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(data)
  })
    .then(res => res.json())
    .then((res) => {
      loading.value = false
      if (res.error) {
        return (errorMessage.value = res.error)
      } else {
        toast.add({
          title: 'Account Registered Successfully 🎉',
          description: 'You can now login to your account.',
          color: 'green'
        })

        navigateTo('/loginpagetocyberrange')
      }
    })
    .catch((error) => {
      loading.value = false
      errorMessage.value = 'Network error, please try again later.'
    })
}
</script>
