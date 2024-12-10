<template>
  <UDashboardPage>
    <UDashboardPanel grow>
      <UDashboardPanelContent class="">
        <Icon
          v-if="loading"
          icon="Spinner"
          class="mt-56 flex w-32 items-center justify-center"
        />

        <div v-if="!loading">
          <UPageGrid class="mt-5">
            <ULandingCard
              v-for="(Challenge, index) in Challenges"
              :key="index"
              :title="Challenge.name"
              orientation="vertical"
              class="cursor-pointer"
              @click="openModal(Challenge)"
            >
              <p
                style="
                  white-space: nowrap;
                  overflow: hidden;
                  text-overflow: ellipsis;
                  display: -webkit-box;
                  -webkit-line-clamp: 1; /* Change this number to limit visible lines */
                  -webkit-box-orient: vertical;
                "
                v-html="Challenge.description"
              />
              <div>
                <UBadge
                  variant="subtle"
                  :color="useBadgeColor(Challenge.category)"
                  :label="Challenge.category"
                  size="md"
                />

                <UBadge
                  variant="outline"
                  :label="Challenge.points + ' Points'"
                  size="md"
                  class="ml-2"
                />

                <UBadge
                  class="ml-2"
                  variant="soft"
                  :label="Challenge.difficulty"
                  size="md"
                />
              </div>
              <UIcon
                v-if="role === 'admin'"
                name="i-heroicons-trash"
                class="absolute right-4 top-4 size-6 cursor-pointer"
                @click.stop="openModalDelete(Challenge)"
              />
            </ULandingCard>

            <ULandingCard
              v-if="!loading && role === 'admin'"
              orientation="vertical"
              class="cursor-pointer"
              @click="isAddChallengeModalOpen = true"
            >
              <UIcon
                name="i-heroicons-plus"
                class="text-primary flex h-20 w-24 justify-center self-center"
              />
            </ULandingCard>
          </UPageGrid>
        </div>

        <!--  Challenge Modal -->
        <UModal v-model="isChallengeModalOpen">
          <UCard
            :ui="{
              ring: '',
              divide: 'divide-y divide-gray-100 dark:divide-gray-800',
            }"
          >
            <template #default>
              <div class="flex flex-col space-y-5 p-4">
                <h1 class="text-3xl font-extrabold">
                  {{ selectedChallenge?.name }}
                </h1>
                <div>
                  <UBadge
                    variant="subtle"
                    :color="useBadgeColor(selectedChallenge?.category || '')"
                    :label="selectedChallenge?.category"
                    size="lg"
                  />

                  <UBadge
                    variant="outline"
                    :label="selectedChallenge?.points + ' Points'"
                    size="lg"
                    class="ml-2"
                  />

                  <UBadge
                    class="ml-2"
                    variant="soft"
                    :label="selectedChallenge?.difficulty"
                    size="lg"
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
                  v-html="selectedChallenge?.description"
                />
              </div>

              <div v-if="selectedChallenge?.attachments != ''" class="p-4">
                <div
                  class="flex flex-col rounded-lg bg-white p-3 shadow-lg dark:bg-gray-800"
                >
                  <div class="mb-4 flex items-center justify-between">
                    <div class="flex items-center">
                      <span
                        class="text-lg font-semibold text-gray-900 dark:text-gray-100"
                        >Attachments</span
                      >
                    </div>

                    <UIcon
                      class="mr-2 size-6 hover:scale-125 hover:cursor-pointer"
                      name="i-heroicons-folder-arrow-down"
                      @click.prevent="downloadAll()"
                    />
                  </div>
                  <div v-if="selectedChallenge" class="flex flex-wrap">
                    <div
                      v-for="(
                        attachment, index
                      ) in selectedChallenge.attachments.split(',')"
                      :key="index"
                      class="mx-auto mb-1 flex w-full justify-between rounded-lg bg-gray-100 p-1 hover:cursor-pointer dark:bg-gray-700"
                    >
                      <!-- dynamic component rendering for icons per extension -->
                      <div class="flex items-center">
                        <Icon
                          :icon="useFileIconMatcher(attachment)"
                          class="ml-2 size-4 align-middle"
                        />
                        <p
                          class="ml-2 align-middle text-lg font-medium text-blue-500 transition-colors duration-200 hover:text-blue-700 dark:text-blue-300 dark:hover:text-blue-400"
                          @click.prevent="downloadAttachment(attachment)"
                        >
                          {{ attachment }}
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <!-- show hints in a cool way like click for reveal -->
              <div v-if="selectedChallenge?.hint != ''" class="p-4">
                <div
                  class="flex cursor-pointer items-center justify-between rounded-lg bg-gray-200 p-3 transition-colors duration-200 hover:bg-gray-300"
                  @click="showHint = !showHint"
                >
                  <div class="flex items-center">
                    <UIcon
                      name="i-heroicons-light-bulb"
                      class="text-primary-500 mr-2"
                    />
                    <span class="font-semibold text-gray-700"
                      >Click for hint, dw it won't lower your points.</span
                    >
                  </div>
                  <UIcon
                    v-if="showHint"
                    name="i-heroicons-light-chevron-up"
                    class="text-gray-500"
                  />
                  <UIcon
                    v-else
                    name="i-heroicons-light-chevron-down"
                    class="text-gray-500"
                  />
                </div>
                <transition name="slide-fade">
                  <p
                    v-if="showHint"
                    class="mt-2 rounded-lg bg-gray-100 p-2 text-sm text-gray-500"
                  >
                    {{ selectedChallenge?.hint }}
                  </p>
                </transition>
              </div>
            </template>
          </UCard>
        </UModal>

        <UModal v-model="isAddChallengeModalOpen">
          <UCard
            :ui="{
              ring: '',
              divide: 'divide-y divide-gray-100 dark:divide-gray-800',
            }"
          >
            <template #header>
              <h1>Add a New Challenge</h1>
            </template>

            <template #default>
              <div class="p-4">
                <label required class="block text-sm font-medium text-current"
                  >Name</label
                >
                <UInput v-model="name" label="Name" />
                <Tiptap
                  class="mt-4"
                  title="Description"
                  :content="description"
                  @update:content="description = $event"
                />

                <label
                  required
                  class="mt-4 block text-sm font-medium text-current"
                  >Points</label
                >
                <UInput v-model="points" label="Points" type="number" />

                <label
                  required
                  class="mt-4 block text-sm font-medium text-current"
                  >Category</label
                >
                <USelectMenu v-model="category" :options="categories" />

                <label
                  required
                  class="mt-4 block text-sm font-medium text-current"
                  >Difficulty</label
                >
                <USelectMenu
                  v-model="difficulty"
                  :options="difficulty_levels"
                />

                <label
                  required
                  class="mt-4 block text-sm font-medium text-current"
                  >Flag</label
                >
                <UInput v-model="flag" :placeholder="defaultFlag" />

                <label
                  required
                  class="mt-4 block text-sm font-medium text-current"
                  >Hint</label
                >

                <UInput v-model="hint" label="Hint" class="mt-2" />

                <label class="text sm mt-4 block font-medium text-current"
                  >Attachments</label
                >
                <input
                  id="attachmentInput"
                  type="file"
                  multiple
                  accept="*"
                  class="block w-full text-sm file:mr-4 file:rounded-full file:border-0 file:px-4 file:py-2 file:text-sm file:font-semibold hover:cursor-pointer"
                  @change="OnChangeAttachments"
                />

                <p v-if="errorMessage" class="mt-5 text-red-500">
                  {{ errorMessage }}
                </p>
              </div>

              <div class="p-4 text-right">
                <UButton :loading="loading" primary @click="addChallenge">
                  Add Challenge
                </UButton>
              </div>
            </template>
          </UCard>
        </UModal>

        <UModal v-model="isDeleteChallengeModalOpen">
          <UCard
            :ui="{
              ring: '',
              divide: 'divide-y divide-gray-100 dark:divide-gray-800',
            }"
          >
            <template #header>
              <h1>Confirm</h1>
            </template>

            <template #default>
              <div class="p-4">
                <p>Are you sure you want to delete this Challenge?</p>
              </div>
            </template>
            <template #footer>
              <div class="flex justify-between">
                <UButton
                  :loading="deleteLoading"
                  primary
                  @click="deleteChallenge(selectedChallenge as Challenge)"
                >
                  Delete Challenge
                </UButton>
                <UButton primary @click="isDeleteChallengeModalOpen = false">
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
definePageMeta({
  middleware: "unauthorized",
});

const apiURL = useRuntimeConfig().public.apiURL;
const Challenges = ref<Challenge[]>([]);
interface Challenge {
  id: number;
  name: string;
  description: string;
  container_names: string[];
  category: string;
  points: string;
  difficulty: string;
  attachments: string;
  hint: string;
}
const showHint = ref(false);
const isAddChallengeModalOpen = ref(false);
const isDeleteChallengeModalOpen = ref(false);
const token = useCookie("token");
const role = useCookie("role");
const loading = ref(false);
const deleteLoading = ref(false);
const name = ref("");
const description = ref("");
const errorMessage = ref("");
const isChallengeModalOpen = ref(false);
const selectedChallenge = ref<Challenge | null>(null);
const attachments = ref<FileList | null>(null);
const OnChangeAttachments = (event: Event) => {
  attachments.value = (event.target as HTMLInputElement).files;
};
const category = ref("");
const points = ref();
const flag = ref("");
const categories = [
  "Web Exploitation",
  "Forensics",
  "Cryptography",
  "Reverse Engineering",
  "Miscellaneous",
  "Network Security",
  "Binary Exploitation",
  "Steganography",
  "Warmup",
];
const hint = ref("");

const difficulty = ref("");
const difficulty_levels = ["Easy", "Medium", "Hard", "Insane"];
const defaultFlag = ref("");

const openModalDelete = (Challenge: Challenge) => {
  selectedChallenge.value = Challenge;
  isDeleteChallengeModalOpen.value = true;
};
const openModal = (Challenge: Challenge) => {
  selectedChallenge.value = Challenge;
  isChallengeModalOpen.value = true;
};

async function getChallenges() {
  loading.value = true;

  const response = await fetch(`${apiURL}/api/v1/admin/get-challenges`, {
    headers: {
      Authorization: `Bearer ${token.value}`,
    },
  });

  const data = await response.json();
  await nextTick();
  if (!response.ok) {
    loading.value = false;
    return alert("Failed to fetch Challenges");
  } else {
    Challenges.value = data.challenges;
    defaultFlag.value = data.defaultFlag;
    loading.value = false;
  }

  loading.value = false;
}

async function addChallenge() {
  loading.value = true;

  if (
    !name.value ||
    !description.value ||
    !category.value ||
    !points.value ||
    !flag.value ||
    !difficulty.value
  ) {
    loading.value = false;

    return (errorMessage.value = "Please fill all the fields");
  }

  const formData = new FormData();
  formData.append("name", name.value);
  formData.append("description", description.value);
  formData.append("category", category.value);
  formData.append("points", points.value.toString());
  formData.append("flag", flag.value);
  formData.append("hint", hint.value);
  formData.append("difficulty", difficulty.value);

  if (attachments.value) {
    for (let i = 0; i < attachments.value.length; i++) {
      formData.append(`file${i}`, attachments.value[i] as File);

    }
  }

  if (points.value <= 0) {
    loading.value = false;
    return (errorMessage.value = "Points must be greater than 0");
  }

  const response = await fetch(`${apiURL}/api/v1/admin/add-challenge`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token.value}`,
    },
    body: formData,
  });

  const data = await response.json();

  if (!response.ok) {
    loading.value = false;

    errorMessage.value = data.error;
  } else {
    getChallenges();

    Challenges.value = data;
    loading.value = false;
    isAddChallengeModalOpen.value = false;
  }

  name.value = "";
  description.value = "";
  category.value = "";
  points.value = 0;
  flag.value = "";
  hint.value = "";
  difficulty.value = "";
  attachments.value = null;
}

async function downloadAll() {
  if (!selectedChallenge.value) {
    return;
  }

  const response = await fetch(
    `${apiURL}/api/v1/shared/download-all?challenge=${selectedChallenge.value.name}`,
    {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token.value}`,
      },
    },
  );

  if (response.ok) {
    const blob = await response.blob();

    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "attachments.zip";
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
  } else {
    const data = await response.json();
    toast.add({
      title: "Error",
      description: data.message,
      color: "red",
    });
  }
}

async function deleteChallenge(Challenge: Challenge) {
  deleteLoading.value = true;
  fetch(`${apiURL}/api/v1/admin/delete-challenge?name=${Challenge.name}`, {
    method: "DELETE",
    headers: {
      Authorization: `Bearer ${token.value}`,
    },
  })
    .then((res) => res.json())
    .then((res) => {
      if (res.error) {
        deleteLoading.value = false;
        return alert(res.error);
      } else {
        deleteLoading.value = false;
        isDeleteChallengeModalOpen.value = false;
        getChallenges();
      }
    });
}

const toast = useToast();
async function downloadAttachment(attachment: string) {
  if (!selectedChallenge.value) {
    return;
  }
  const response = await fetch(
    `${apiURL}/api/v1/shared/download-attachment?filename=` +
      attachment +
      `&challenge=${selectedChallenge.value.name}`,
    {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token.value}`,
      },
    },
  );

  if (response.ok) {
    const blob = await response.blob();

    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = attachment;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
  } else {
    const data = await response.json();
    toast.add({
      title: "Error",
      description: data.message,
      color: "red",
    });
  }
}

onMounted(() => {
  getChallenges();
});
</script>
