<template>
    <UDashboardPage>
        <UDashboardPanel grow>
            <UDashboardNavbar title="Jeopardy" />

            <UDashboardPanelContent class="">
                <Icon v-if="loading" icon="Spinner" class="mx-10 flex w-32 items-center justify-center" />

                <div v-if="!loading && Challenges">
                    <UPageGrid class="mt-5">
                        <ULandingCard v-for="(Challenge, index) in Challenges" :key="index" :title="Challenge.issolved
                            ? Challenge.name + ' ✅'
                            : Challenge.name
                            " orientation="vertical" class="" :class="{
        'cursor-pointer': !Challenge.issolved,
        'opacity-50': Challenge.issolved
    }" @click="openModal(Challenge)">

                            <p style="
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        display: -webkit-box;
        -webkit-line-clamp: 1; /* Change this number to limit visible lines */
        -webkit-box-orient: vertical;
      " v-html="Challenge.description" />
                            <div>
                                <UBadge variant="subtle" :color="useBadgeColor(Challenge.category)"
                                    :label="Challenge.category" size="md" />

                                <UBadge variant="outline" :label="Challenge.points + ' Points'" size="md" class="ml-2" />

                                <UBadge class="ml-2" variant="soft" :label="Challenge.difficulty" size="md" />
                            </div>
                        </ULandingCard>
                    </UPageGrid>
                </div>

                <!--  Challenge Modal -->
                <UModal v-model="isChallengeModalOpen">
                    <UCard :ui="{
                        ring: '',
                        divide: 'divide-y divide-gray-100 dark:divide-gray-800'
                    }">
                        <template #default>
                            <div class="flex flex-col space-y-5 p-4">
                                <h1 v-if="!selectedChallenge?.issolved" class="text-2xl font-extrabold">
                                    {{ selectedChallenge?.name }}
                                </h1>
                                <h1 v-if="selectedChallenge?.issolved" class="text-2xl font-extrabold">
                                    <span :style="{
                                        textDecoration:
                                            selectedChallenge?.issolved
                                                ? 'line-through'
                                                : 'none'
                                    }">
                                        {{ selectedChallenge?.name }}
                                    </span>

                                    <UIcon name="i-heroicons-check-circle" class="ml-2 text-2xl text-green-500" />
                                </h1>
                                <div>
                                    <UBadge variant="subtle" :color="useBadgeColor(
                                        selectedChallenge?.category
                                        || 'primary'
                                    )
                                        " :label="selectedChallenge?.category" size="md" />

                                    <UBadge variant="outline" :label="selectedChallenge?.points
                                        + ' Points'
                                        " size="sm" class="ml-2" />

                                    <UBadge class="ml-2" variant="soft" :label="selectedChallenge?.difficulty" size="sm" />

                                    <UBadge class="ml-2" variant="solid" :label="selectedChallenge?.solves
                                        + ' Solved it'
                                        " size="sm" />
                                </div>
                                <p style="
                    overflow: hidden;
                    display: -webkit-box;
                    -webkit-box-orient: vertical;
                    word-wrap: break-word; /* Allows long words to break */
                    word-break: break-word; /* Ensures that text can break at any character */
                  " v-html="selectedChallenge?.description" />

                            </div>

                            <div v-if="selectedChallenge?.attachments != ''" class="p-4">
                                <div class="flex flex-col rounded-lg bg-white p-3 shadow-lg dark:bg-gray-800">
                                    <div class="mb-4 flex items-center justify-between">
                                        <div class="flex items-center">
                                            <span
                                                class="text-lg font-semibold text-gray-900 dark:text-gray-100">Attachments</span>
                                        </div>

                                        <UIcon class="mr-2 size-6 hover:scale-125 hover:cursor-pointer"
                                            name="i-heroicons-folder-arrow-down" @click.prevent="downloadAll()" />
                                    </div>
                                    <div v-if="selectedChallenge?.attachments" class="flex flex-wrap">
                                        <div v-for="(
                        attachment, index
                      ) in selectedChallenge?.attachments.split(
                          ','
                      )" :key="index"
                                            class="mx-auto mb-1 flex w-full justify-between rounded-lg bg-gray-100 p-1 hover:cursor-pointer dark:bg-gray-700">
                                            <div class="flex items-center">
                                                <Icon :icon="useFileIconMatcher(
                                                    attachment
                                                )
                                                    " class="size-4" />
                                                <p class="ml-2 text-lg font-extrabold text-blue-500 transition-colors duration-200 hover:text-blue-700 dark:text-blue-300 dark:hover:text-blue-400"
                                                    @click.prevent="
                                                        downloadAttachment(
                                                            attachment
                                                        )
                                                        ">
                                                    {{ attachment }}
                                                </p>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <!-- show hints in a cool way like click for reveal -->
                            <div v-if="selectedChallenge?.hint != ''" class="p-4">
                                <div class="flex cursor-pointer items-center justify-between rounded-lg bg-gray-200 p-3 transition-colors duration-200 hover:bg-gray-300"
                                    @click="showHint = !showHint">
                                    <div class="flex items-center">
                                        <UIcon name="i-heroicons-light-bulb" class="text-primary-500 mr-2" />
                                        <span class="font-semibold text-gray-700">Click for hint, dw it won't lower
                                            your points.</span>
                                    </div>
                                    <UIcon v-if="showHint" name="i-heroicons-light-chevron-up" class="text-gray-500" />
                                    <UIcon v-else name="i-heroicons-light-chevron-down" class="text-gray-500" />
                                </div>
                                <transition name="slide-fade">
                                    <p v-if="showHint" class="mt-2 rounded-lg bg-gray-100 p-2 text-sm text-gray-500">
                                        {{ selectedChallenge?.hint }}
                                    </p>
                                </transition>
                            </div>

                            <!-- submit flag -->
                            <div v-if="!selectedChallenge?.issolved" class="p-4">
                                <UInput v-model="flag" label="Flag" icon="i-heroicons-flag" :placeholder="defaultFlag" />

                                <div class="mt-4 flex justify-end">
                                    <UButton :loading="loading" primary class="mt-2" size="lg" @click="submitFlag">
                                        Submit Flag
                                    </UButton>
                                </div>
                            </div>
                        </template>
                    </UCard>
                </UModal>

                <div v-if="message != ''" class="flex items-center justify-center p-4">
                    <ULandingSection :title="message" description="While you're waiting, why not dive into the labs? 🧪" />
                </div>

                <div v-if="release_date != ''" class="flex items-center justify-center p-4">
                    <div class="flex flex-col items-center justify-center rounded-lg p-3">
                        <p>The CTF will start in:</p>
                        <br>

                        <Countdown v-slot="{ days, hours, minutes, seconds }" :time="diff">
                            <div class="text-center">
                                <p
                                    class="animate-pulse cursor-pointer text-8xl font-extrabold text-black dark:text-white transition-transform hover:scale-105">
                                    {{ days }}d : {{ hours }}h : {{ minutes }}m
                                    : {{ seconds }}s 🚀
                                </p>
                            </div>
                        </Countdown>
                    </div>
                </div>

                <div v-if="!loading && role === 'user'"
                    class="fixed bottom-1 right-1 m-4 rounded-lg bg-gray-800 bg-opacity-75 p-4 text-3xl font-extrabold text-green-500 shadow-lg transition-transform duration-300 hover:scale-105">
                    <p class="flex items-center space-x-2">
                        <span>🚀</span>
                        <span class="text-primary-400">Score:</span>
                        <span class="text-white">{{ score }}</span>
                    </p>
                </div>

            </UDashboardPanelContent>
        </UDashboardPanel>
    </UDashboardPage>
</template>

<script setup lang="ts">
const apiURL = useRuntimeConfig().public.apiURL
const Challenges = ref<Challenge[]>([])
interface Challenge {
    id: number
    name: string
    description: string
    container_names: string[]
    category: string
    points: string
    difficulty: string
    attachments: string
    hint: string
    issolved: boolean
    solves: number
}
const showHint = ref(false)
const token = useCookie('token')
const loading = ref(false)
const isChallengeModalOpen = ref(false)
const selectedChallenge = ref<Challenge | null>(null)
const toast = useToast()
const flag = ref('')
const release_date = ref('')
const message = ref('')
const score = ref(0)
const role = useCookie('role')

definePageMeta({
    layout: 'dashboard',
})

const defaultFlag = ref('')
const openModal = (Challenge: Challenge) => {
    selectedChallenge.value = Challenge
    isChallengeModalOpen.value = true
}

const diff = ref(0)
async function getCTF() {
    loading.value = true

    const response = await fetch(`${apiURL}/api/v1/shared/get-jeopardyctf`, {
        headers: {
            Authorization: `Bearer ${token.value}`,
        },
    })

    const data = await response.json()
      //await nextTick()
    if (!response.ok) {
        loading.value = false
        return alert('Failed to fetch Challenges')
    } else {
        if (data.challenges) {
            Challenges.value = data.challenges
            score.value = data.score
        }

        if (data.defaultFlag) {
            defaultFlag.value = data.defaultFlag
        }

        if (data.release_date) {
            release_date.value = data.release_date
            const now = new Date()
            const releaseDate = new Date(release_date.value)
            diff.value = releaseDate.getTime() - now.getTime()
        }

        if (data.message) {
            message.value = data.message
        }
    }

    loading.value = false
}

async function downloadAttachment(attachment: string) {
    const response = await fetch(
        `${apiURL}/api/v1/shared/download-attachment?filename=`
        + attachment
        + `&challenge=${selectedChallenge.value?.name}`,
        {
            method: 'GET',
            headers: {
                Authorization: `Bearer ${token.value}`,
            },
        },
    )

    if (response.ok) {
        const blob = await response.blob()

        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = attachment
        document.body.appendChild(a)
        a.click()
        window.URL.revokeObjectURL(url)
    } else {
        const data = await response.json()
        toast.add({
            title: 'Error',
            description: data.message,
            color: 'red',
        })
    }
}

async function downloadAll() {
    if (selectedChallenge.value && selectedChallenge.value.name) {
        const response = await fetch(
            `${apiURL}/api/v1/shared/download-all?challenge=${selectedChallenge.value.name}`,
            {
                method: 'GET',
                headers: {
                    Authorization: `Bearer ${token.value}`,
                },
            },
        )

        if (response.ok) {
            const blob = await response.blob()

            const url = window.URL.createObjectURL(blob)
            const a = document.createElement('a')
            a.href = url
            a.download = 'attachments.zip'
            document.body.appendChild(a)
            a.click()
            window.URL.revokeObjectURL(url)
        } else {
            const data = await response.json()
            toast.add({
                title: 'Error',
                description: data.message,
                color: 'red',
            })
        }
    }
}

const submitFlag = async () => {
    if (!selectedChallenge.value) {
        return
    }

    const response = await fetch(
        `${apiURL}/api/v1/shared/submit-flag?flag=`
        + flag.value
        + '&challenge='
        + selectedChallenge.value.name,
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
    } else {
        await toast.add({
            icon: 'i-heroicons-check-circle',
            title: 'Success',
            description: data.message,
            color: 'green',
        })

        await toast.add({
            title: 'Points',
            description:
                'You earned '
                + selectedChallenge.value.points
                + ' points, keep it up! 🎉',
            color: 'green',
        })

        isChallengeModalOpen.value = false
    }

    flag.value = ''
    getCTF()
}

onMounted(() => {
    getCTF()
})
</script>
