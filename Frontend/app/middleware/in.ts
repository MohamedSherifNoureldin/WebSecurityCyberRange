export default defineNuxtRouteMiddleware((to) => {
  const token = useCookie('token')
  if (!token.value && to?.name !== 'loginpagetocyberrange' && to?.name !== 'noaccount') {
    abortNavigation()
    return navigateTo('/loginpagetocyberrange')
  }
})
