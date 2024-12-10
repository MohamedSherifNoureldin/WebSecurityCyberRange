<template>
  <UDashboardPage>
    <UDashboardPanel grow>
      <UDashboardNavbar :title="category" />

      <UDashboardPanelContent class="">
        <UBreadcrumb
          divider="/"
          :links="[
            { label: 'Labs', to: '/labs' },
            { label: category }
          ]"
        />
        <Icon v-if="loading" icon="Spinner" class="mx-10 flex w-32 items-center justify-center" />

        <div v-if="!loading">
          <UPageGrid class="mt-5">
            <ULandingCard
              v-for="(lab, index) in labs"
              :key="index"
              orientation="vertical"
              class=""
              :class="{
                'relative cursor-pointer': !lab.issolved,
                'opacity-50': lab.issolved
              }"
              @click="openModal(lab)"
            >
              <template #title>
                <div class="flex w-full items-center justify-between">
                  <span style="
                    white-space: nowrap;
                    overflow: hidden;
                    text-overflow: ellipsis;
                    display: -webkit-box;
                    -webkit-line-clamp: 1; /* Change this number to limit visible lines */
                    -webkit-box-orient: vertical;
                  " v-if="!lab.issolved">{{ lab.name }}</span>
                  <span style="
                    white-space: nowrap;
                    overflow: hidden;
                    text-overflow: ellipsis;
                    display: -webkit-box;
                    -webkit-line-clamp: 1; /* Change this number to limit visible lines */
                    -webkit-box-orient: vertical;
                  " v-if="lab.issolved" class="line-through">{{ lab.name + " ✅" }}</span>

                  <div>
                  <UIcon
                  v-if="role === 'admin' && lab.shown"
                  name="i-heroicons-eye-20-solid"
                  class="mr-3 size-6  dark:text-gray-300"
                  />

                  <UIcon
                  v-if="role === 'admin' && !lab.shown"
                  name="i-heroicons-eye-slash-20-solid"
                  class="mr-3 size-6 text-gray-400 dark:text-gray-600"
                  />

                  <UIcon
                    v-if="role === 'admin'"
                    name="i-heroicons-trash"
                    class="size-6 cursor-pointer hover:text-red-500"
                    @click.stop="openModalDelete(lab)"
                  />
</div>
                </div>
              </template>
              <p
                style="
                  white-space: nowrap;
                  overflow: hidden;
                  text-overflow: ellipsis;
                  display: -webkit-box;
                  -webkit-line-clamp: 1; /* Change this number to limit visible lines */
                  -webkit-box-orient: vertical;
                "
                v-html="lab.description"
              />



              <div v-if="lab.isctf === 'true'">
                <UBadge variant="subtle" label="CTF" size="lg" />
              </div>
            </ULandingCard>
            <ULandingCard
              v-if="!loading && role === 'admin'"
              orientation="vertical"
              class="cursor-pointer"
              @click="isAddLabModalOpen = true"
            >
              <UIcon name="i-heroicons-plus" class="text-primary flex h-10 w-14 justify-center self-center" />
            </ULandingCard>
          </UPageGrid>
        </div>

        <!-- Start Lab Modal -->
        <UModal v-model="isLabModalOpen">
          <UCard
            :ui="{
              ring: '',
              divide: 'divide-y divide-gray-100 dark:divide-gray-800'
            }"
          >
            <template #default>
              <div class="flex flex-col space-y-5 p-4">

              <div class="flex flex-row items-center justify-between">
                <h1
                  v-if="!selectedLab?.issolved"
                  class="text-2xl font-extrabold flex-1"
                  style="
                    overflow: hidden;
                    display: -webkit-box;
                    -webkit-box-orient: vertical;
                    word-wrap: break-word;
                    word-break: break-word;
                  "
                >
                  {{ selectedLab?.name }}
                </h1>

                <h1
                  v-if="selectedLab?.issolved"
                  class="text-2xl font-extrabold flex-1"
                  style="
                    overflow: hidden;
                    display: -webkit-box;
                    -webkit-box-orient: vertical;
                    word-wrap: break-word;
                    word-break: break-word;
                  "
                >
                  <span
                    :style="{
                      textDecoration:
                        selectedLab?.issolved
                          ? 'line-through'
                          : 'none'
                    }"
                  >
                    {{ selectedLab?.name }}
                  </span>

                  <UIcon
                    name="i-heroicons-check-circle"
                    class="ml-2 text-2xl text-green-500"
                  />
                </h1>

                <UToggle
                  v-if="role === 'admin' && !hiddenLoading"
                  on-icon="i-heroicons-eye-20-solid"
                  off-icon="i-heroicons-eye-slash-20-solid"
                  v-model="selectedLab.shown"
                  size="lg"
                  @change="updateLabStatus()"
                />

                <UToggle
                  v-if="role === 'admin' && hiddenLoading"
                  on-icon="i-heroicons-eye-20-solid"
                  off-icon="i-heroicons-eye-slash-20-solid"
                  size="lg"
                  loading
                />

              </div>
                    <p
                  style="
                    overflow: hidden;
                    display: -webkit-box;
                    -webkit-box-orient: vertical;
                    word-wrap: break-word; /* Allows long words to break */
                    word-break: break-word; /* Ensures that text can break at any character */
                  "
                  v-html="selectedLab?.description"
                />
              </div>
              <UDivider size="sm" v-if="role==='admin'"/>
               <!-- show the solves of the lab -->
               <div class="p-4" v-if="role==='admin'">
                 <h1 class="text-xl font-semibold mb-4">
                   Solved by:
                 </h1>

                 <div v-if="selectedLab && solves[selectedLab.name]" class="overflow-x-auto">
                   <table class="table-auto w-full border-collapse border border-gray-300">
                     <thead>
                       <tr >
                         <th class="border border-gray-300 px-4 py-2 text-left">Student ID</th>
                         <th class="border border-gray-300 px-4 py-2 text-left">Name</th>
                         <th class="border border-gray-300 px-4 py-2 text-left">Email</th>
                       </tr>
                     </thead>
                     <tbody>
                       <tr v-for="solve in solves[selectedLab.name]" :key="solve.id" >
                         <td class="border border-gray-300 px-4 py-2">{{ solve.id }}</td>
                         <td class="border border-gray-300 px-4 py-2">{{ solve.name }}</td>
                         <td class="border border-gray-300 px-4 py-2">{{ solve.email }}</td>
                       </tr>
                     </tbody>
                   </table>
                 </div>

                 <div v-else class="  mt-4">
                   No one solved this lab yet.
                 </div>
               </div>
              <!-- submit flag -->
              <div class="p-4">
                <UInput v-if="!selectedLab?.issolved" v-model="flag" label="Flag" icon="i-heroicons-flag" placeholder="AUCYBER{flag}" />

                <div v-if="!selectedLab?.issolved" class="mt-4 flex justify-between">
                  <UButton v-if="!flagLoading" primary class="mt-2" size="lg" @click="submitFlag">
                    Submit Flag
                  </UButton>

                  <UButton loading v-if="flagLoading" primary class="mt-2" size="lg">
                     Submitting...
                  </UButton>

                  <UButton v-if="!runLoading" color="green" class="mt-2" size="lg" @click="startLab">
                    Start Lab
                  </UButton>

                    <UButton loading v-if="runLoading" color="green" class="mt-2" size="lg">
                    Starting...
                    </UButton>
                </div>

                <div v-if="selectedLab?.issolved" class="mt-4 flex justify-end">
                  <UButton :loading="runLoading" color="green" class="mt-2" size="lg" @click="startLab">
                    Start Lab
                  </UButton>
                </div>

                <UAlert
                  v-if="errorMessage"
                  color="red"
                  icon="i-heroicons-information-circle-20-solid"
                  :title="errorMessage"
                />

                <div v-if="username" class="flex flex-col items-center justify-center space-y-5">
                  <p class="flex items-center text-lg font-bold">
                    The Lab Started
                    <UIcon name="i-heroicons-check-circle" class="ml-2 size-8" />
                  </p>

                  <NuxtLink
                    :to="{
                      path: `/terminal`,
                      query: {
                        container_names:
                          selectedLab?.container_names,
                        labname: selectedLab?.name,
                        username: username,
                        password: password
                      }
                    }"
                    target="_blank"
                    class="text-center"
                  >
                    <UBadge
                      variant="subtle"
                      class="text-primary rounded-full p-1 text-lg font-bold"
                    >Click Here to
                      access the
                      lab</UBadge>
                  </NuxtLink>
                </div>
              </div>



            </template>
          </UCard>
        </UModal>

        <UModal v-model="isAddLabModalOpen">
          <UCard
            :ui="{
              ring: '',
              divide: 'divide-y divide-gray-100 dark:divide-gray-800'
            }"
          >
            <template #header>
              <h1>Add a New Lab</h1>
            </template>

            <template #default>
              <div class="p-4">
                <label class="block text-sm font-medium text-current">Name</label>
                <UInput v-model="name" label="Name" />

                <Tiptap
                  class=" mt-4"
                  title="Description"
                  :content="description"
                  @update:content="description = $event"
                />

                <label class="text sm mt-4 block font-medium text-current">Compose File</label>
                <input
                  id="composeFileInput"
                  type="file"
                  accept=".yaml,.yml"
                  class="block w-full text-sm file:mr-4 file:rounded-full file:border-0 file:px-4 file:py-2 file:text-sm file:font-semibold hover:cursor-pointer"
                  @change="OnChangeComposeFile"
                >

                <label class="text sm mt-4 block font-medium text-current">Is CTF</label>

                <UToggle v-model="isCTF" />

                <p v-if="errorMessage" class="mt-5 text-red-500">
                  {{ errorMessage }}
                </p>
              </div>

              <div class="p-4 text-right">
                <UButton :loading="loading" primary @click="addLab">
                  Add Lab
                </UButton>
              </div>
            </template>
          </UCard>
        </UModal>

        <UModal v-model="isDeleteLabModalOpen">
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
                <p>Are you sure you want to delete this lab?</p>
              </div>
            </template>
            <template #footer>
              <div class="flex justify-between">
                <UButton
                  :loading="deleteLoading"
                  primary
                  color="red"
                  @click="deleteLab(selectedLab as Lab)"
                >
                  Delete Lab
                </UButton>
                <UButton primary @click="isDeleteLabModalOpen = false">
                  Cancel
                </UButton>
              </div>
            </template>
          </UCard>
        </UModal>

        <UNotifications />
      </UDashboardPanelContent>
    </UDashboardPanel>
  </UDashboardPage>
</template>

<script setup lang="ts">
const apiURL = useRuntimeConfig().public.apiURL
const labs = ref<Lab[]>([])
interface Lab {
  id: number
  name: string
  description: string
  container_names: string[]
  isctf: string
  issolved: boolean
  shown: boolean
}

const solves = ref<Record<string, Solve[]>>({});

interface Solve {
  id: string;
  name: string;
  email: string;
}


const isAddLabModalOpen = ref(false)
const isDeleteLabModalOpen = ref(false)
const token = useCookie('token')
const role = useCookie('role')
const loading = ref(false)
const hiddenLoading = ref(false)
const runLoading = ref(false)
const deleteLoading = ref(false)
const name = ref('')
const flag = ref('')
const description = ref('<p>Write a description for the lab</p>')
const composeFiles = ref<FileList | null>(null)
const errorMessage = ref('')
const isLabModalOpen = ref(false)
const selectedLab = ref<Lab | null>(null)
const username = ref('')
const password = ref('')
const category = (useRoute().params as { category: string }).category
const isCTF = ref(false)
const toast = useToast()
const flagLoading = ref(false);

const updateLabStatus = async () => {
  hiddenLoading.value = true;

  const response = await fetch(
    `${apiURL}/api/v1/admin/update-lab-status?name=${selectedLab.value?.name}&shown=${selectedLab.value?.shown}`,
    {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${token.value}`,
      },
    }
  );

  const data = await response.json();
  hiddenLoading.value = false;

  if (!response.ok) {
    toast.add({
      title: 'Error',
      description: data.error,
      color: 'red',
    });
  } else {
    toast.add({
      title: 'Success',
      description: 'Lab status updated successfully',
      color: 'green',
    });


    labs.value = labs.value.map((lab) => {
      if (lab.id === selectedLab.value.id) {
        lab.shown = selectedLab.value.shown;
      }
      return lab;
    });
  }
};


const openModalDelete = (lab: Lab) => {
  selectedLab.value = lab
  isDeleteLabModalOpen.value = true
}
const openModal = (lab: Lab) => {
  selectedLab.value = lab
  isLabModalOpen.value = true
}

definePageMeta({
  layout: 'dashboard',
})

const OnChangeComposeFile = (event: Event) => {
  composeFiles.value = (event.target as HTMLInputElement).files
}
async function getLabs () {
  loading.value = true

  const response = await fetch(
        `${apiURL}/api/v1/shared/get-labs?category=${category}`,
        {
          headers: {
            Authorization: `Bearer ${token.value}`,
          },
        },
  )

  const data = await response.json()
  await nextTick()
  if (!response.ok) {
    loading.value = false
    return alert('Failed to fetch labs')
  } else {
    labs.value = data.labs;
    solves.value = data.solves;
    loading.value = false
  }

  loading.value = false
}

const submitFlag = async () => {
  flagLoading.value=true;
  if (!selectedLab.value) {
    return
  }

  if (flag.value === '') {
    toast.add({
      title: 'Error',
      description: 'Please enter a flag',
      color: 'red',
    })

    return
  }

  const response = await fetch(
        `${apiURL}/api/v1/shared/submit-lab-flag?flag=`
        + flag.value
        + '&lab='
        + selectedLab.value.name,

        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token.value}`,
            'Content-Type': 'application/json',
          },
        },
  )

  const data = await response.json()

  if (!response.ok) {
    toast.add({
      title: 'Error',
      description: data.error,
      color: 'red',
    })

    flagLoading.value=false;

  } else {
    toast.add({
      icon: 'i-heroicons-check-circle',
      title: 'You solved the lab successfully,  keep it up! 🎉',
      description: data.message,
      color: 'green',
    })

    flagLoading.value=false;

    isLabModalOpen.value = false
  }

  flag.value = ''
  getLabs()
}

async function addLab () {
  if (!name.value || !description.value || composeFiles.value === null ) {
    return (errorMessage.value = 'Please fill all the fields')
  }

  const formData = new FormData()
  formData.append('name', name.value)
  formData.append('description', description.value)
  formData.append('composefile', composeFiles.value[0] as File)
  formData.append('category', category)
  formData.append('isctf', isCTF.value.toString())

  loading.value = true
  const response = await fetch(`${apiURL}/api/v1/admin/add-lab`, {
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
    getLabs()

    labs.value = data
    loading.value = false
    isAddLabModalOpen.value = false
    errorMessage.value = ''
    name.value = ''
    description.value = ''
  }
}

  function startLab () {
  runLoading.value = true
  const queryParams = selectedLab.value?.container_names
    .map(name => `container_names=${encodeURIComponent(name)}`)
    .join('&')

  const finalQueryParams
        = queryParams + `&labname=${selectedLab.value?.name}`

  const url = `/terminal?${finalQueryParams}`

  window.open(url, '_blank')

  runLoading.value = false
}

async function deleteLab (lab: Lab) {
  deleteLoading.value = true
  await fetch(`${apiURL}/api/v1/admin/delete-lab?name=${lab.name}`, {
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
        isDeleteLabModalOpen.value = false
        getLabs()
      }
    })
}

onMounted(() => {
  getLabs()
})
</script>
