<template>
  <UDashboardPage>
    <UDashboardPanel grow>
      <UDashboardNavbar title="Categories" />

      <UDashboardPanelContent class="">
        <Icon
          v-if="loading"
          icon="Spinner"
          class="mx-10 flex w-32 items-center justify-center"
        />

        <div v-if="!loading">
          <UPageGrid class="mt-5">
            <ULandingCard
              v-for="(category, index) in categories"
              :key="index"
              :title="category.name"
              :description="`${category.number_of_labs} ${
                category.number_of_labs === 1 ? 'lab' : 'labs'
              }`"
              orientation="vertical"
              class="relative cursor-pointer"
              @click="$router.push('/labs/' + category.name)"
            >
              <template #title>
                <div
                  class="flex w-full items-center justify-between"
                >
                  <span style="
                    white-space: nowrap;
                    overflow: hidden;
                    text-overflow: ellipsis;
                    display: -webkit-box;
                    -webkit-line-clamp: 1; /* Change this number to limit visible lines */
                    -webkit-box-orient: vertical;
                  ">{{ category.name }}</span>
                  <UIcon
                    v-if="role === 'admin'"
                    name="i-heroicons-trash"
                    class="ml-2 size-6 cursor-pointer hover:text-red-500"
                    @click.stop="openModalDelete(category)"
                  />
                </div>
              </template>
            </ULandingCard>

            <ULandingCard
              v-if="!loading && role === 'admin'"
              orientation="vertical"
              class="cursor-pointer"
              @click="isAddCategoryModalOpen = true"
            >
              <UIcon
                name="i-heroicons-plus"
                class="text-primary flex h-10 w-14 justify-center self-center"
              />
            </ULandingCard>
          </UPageGrid>
        </div>

        <UModal v-model="isAddCategoryModalOpen">
          <UCard
            :ui="{
              ring: '',
              divide: 'divide-y divide-gray-100 dark:divide-gray-800'
            }"
          >
            <template #header>
              <h1>Add a New Category</h1>
            </template>

            <!-- add name, description ,  -->
            <template #default>
              <div class="p-4">
                <label
                  class="block text-sm font-medium text-current"
                >Name</label>
                <UInput v-model="name" categoryel="Name" />

                <p
                  v-if="errorMessage"
                  class="mt-5 text-red-500"
                >
                  {{ errorMessage }}
                </p>
              </div>

              <div class="p-4 text-right">
                <UButton
                  :loading="loading"
                  primary
                  @click="addCategory"
                >
                  Add Category
                </UButton>
              </div>
            </template>
          </UCard>
        </UModal>

        <UModal v-model="isDeleteCategoryModalOpen">
          <UCard
            :ui="{
              ring: '',
              divide: 'divide-y divide-gray-100 dark:divide-gray-800'
            }"
          >
            <template #header>
              <h1 class="font-semibold">
                Confirm
              </h1>
            </template>

            <template #default>
              <div>
                <p>
                  Are you sure you want to delete this
                  category?
                </p>
              </div>
            </template>
            <template #footer>
              <div class="flex justify-between">
                <UButton
                  :loading="deleteLoading"
                  primary
                  color="red"
                  @click="deleteCategory(selectedCategory)"
                >
                  Delete Category
                </UButton>
                <UButton
                  primary
                  @click="isDeleteCategoryModalOpen = false"
                >
                  Cancel
                </UButton>
              </div>
            </template>
          </UCard>
        </UModal>
      </UDashboardPanelContent>
    </UDashboardPanel>
  </UDashboardPage>
</template>

<script setup lang="ts">
const apiURL = useRuntimeConfig().public.apiURL

const categories = ref<LabCategory[]>([])

const isAddCategoryModalOpen = ref(false)
const isDeleteCategoryModalOpen = ref(false)
const token = useCookie('token')
const role = useCookie('role')
const loading = ref(false)
const deleteLoading = ref(false)
const name = ref('')
const errorMessage = ref('')
const selectedCategory = ref<LabCategory>({
  name: '',
  number_of_labs: 0,
})

definePageMeta({
  layout: 'dashboard',
})

const openModalDelete = (category: LabCategory) => {
  selectedCategory.value = category
  isDeleteCategoryModalOpen.value = true
}

async function getCategories () {
  loading.value = true

  const response = await fetch(`${apiURL}/api/v1/shared/get-categories`, {
    headers: {
      Authorization: `Bearer ${token.value}`,
    },
  })

  const data = await response.json()
  await nextTick()
  if (!response.ok) {
    loading.value = false
    return alert('Failed to fetch categories')
  } else {
    categories.value = data
    loading.value = false
  }

  loading.value = false
}

async function addCategory () {
  if (!name.value) {
    return (errorMessage.value = 'Please fill in the name field')
  }

  const formData = new FormData()
  formData.append('name', name.value)

  loading.value = true
  const response = await fetch(`${apiURL}/api/v1/admin/add-category`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token.value}`,
    },
    body: formData,
  })

  const data = await response.json()

  if (!response.ok) {
    loading.value = false

    errorMessage.value = data.error
  } else {
    getCategories()

    categories.value = data
    loading.value = false
    isAddCategoryModalOpen.value = false
    errorMessage.value = ''
  }
}

async function deleteCategory (category: LabCategory) {
  deleteLoading.value = true
  fetch(`${apiURL}/api/v1/admin/delete-category?name=${category.name}`, {
    method: 'DELETE',
    headers: {
      Authorization: `Bearer ${token.value}`,
    },
  })
    .then(res => res.json())
    .then((res) => {
      if (res.error) {
        deleteLoading.value = false
        return alert(res.error)
      } else {
        deleteLoading.value = false
        isDeleteCategoryModalOpen.value = false
        getCategories()
      }
    })
}

onMounted(() => {
  getCategories()
})
</script>
