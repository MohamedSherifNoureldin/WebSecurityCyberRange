export const useDashboard = createSharedComposable(() => {
  const route = useRoute()
  const router = useRouter()
  const isHelpSlideoverOpen = ref(false)
  const role = useCookie('role')

  defineShortcuts({
    'g-h': () => router.push('/'),
    'g-l': () => router.push('/labs'),
    'g-u': () => {
      if (role.value === 'admin') {
        router.push('/users')
      }
    },
    'g-c': () => router.push('/ctf/challenges'),
  })

  watch(
    () => route.fullPath,
    () => {
      isHelpSlideoverOpen.value = false
    },
  )

  return {
    isHelpSlideoverOpen,
  }
})
