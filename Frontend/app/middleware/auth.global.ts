export default defineNuxtRouteMiddleware((to) => {
  const token = useCookie('token')
  const role = useCookie('role')

  if (
    !token.value
    && to?.name !== 'index'
    && to?.name !== 'noaccount'
    && to?.name !== 'loginpagetocyberrange'
    && to?.name !== 'forgetpasswordman'
  ) {
    abortNavigation()
    return navigateTo('/')
  } else if (
    token.value
    && (to?.name === 'loginpagetocyberrange'
    || to?.name === 'noaccount'
    || to?.name === 'forgetpasswordman'
    )
  ) {
    abortNavigation()
    return navigateTo('/dashboard')
  }
})
