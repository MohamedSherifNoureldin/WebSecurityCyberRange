export type { Avatar } from '#ui/types'
declare global {
  interface Range {
    start: Date
    end: Date
  }

  type LabCategory = {
    name: string
    number_of_labs: number
  }
}

export { }
