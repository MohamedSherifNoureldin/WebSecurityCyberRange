import { existsSync, readdirSync, unlinkSync, writeFileSync } from 'node:fs'

type Snippet = {
  [key: string]: {
    prefix: string
    body: string[]
    description: string
  }
}

const srcDirectory = './app/components/global/Icon/'
const icons: string[] = []
const subDirectories: string[] = []
let iconOptions = ''
const iconsSnippetBody: Snippet = {
  '✪': {
    prefix: 'icn',
    body: ['<Icon icon="${1|choices|}" class="${2:cssClasses}" />'],
    description: 'Normal Icon component',
  },
}

readdirSync(srcDirectory, { withFileTypes: true })
  .filter(item => !item.isDirectory() && item.name !== 'index.vue')
  .forEach(item => icons.push(item.name.replace('.vue', '')))

readdirSync(srcDirectory, { withFileTypes: true })
  .filter(item => item.isDirectory())
  .forEach(item => subDirectories.push(item.name))

subDirectories.forEach((subDirectory) => {
  readdirSync(`${srcDirectory}${subDirectory}`, { withFileTypes: true })
    .filter(item => !item.isDirectory() && item.name !== 'index.vue')
    .forEach(item => icons.push(`${subDirectory}/${item.name.replace('.vue', '')}`))
})

iconOptions = icons.join(',')

iconsSnippetBody['✪'].body[0] = `<Icon icon="\${1|${iconOptions}|}" class="\${2:cssClasses}" />`

if (existsSync('./.vscode/icons.code-snippets')) {
  unlinkSync('./.vscode/icons.code-snippets')
}

writeFileSync('./.vscode/icons.code-snippets', JSON.stringify(iconsSnippetBody, null, 2))

console.log('Snippet file generated successfully!')
