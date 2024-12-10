export default defineNuxtRouteMiddleware(async (to, from) => {
  const role = useCookie('role')
  const apiURL = useRuntimeConfig().public.apiURL

  if (role.value === 'user') {
    abortNavigation()
    return navigateTo('/unauthorized')
  } else {
    const res = await fetch(`${apiURL}/api/v1/shared/is-admin`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${useCookie('token').value}`
      }
    })

    if (res.status != 200) {
      abortNavigation()
      return navigateTo('/unauthorized')
    } else {
      return
    }
  }
})
