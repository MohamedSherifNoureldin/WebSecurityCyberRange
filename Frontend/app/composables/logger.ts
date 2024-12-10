import { consola } from 'consola'

const isDev = import.meta.dev

export const useLogger = (tag: 'API' | 'WS' | 'Other' | 'Props') => consola.withTag(tag)
