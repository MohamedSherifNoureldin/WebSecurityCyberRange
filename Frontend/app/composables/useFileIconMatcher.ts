export const useFileIconMatcher = (attachment: string) => {
  const extension = attachment.split('.').pop()
  const extensionMap = {
    png: 'Picture',
    jpg: 'Picture',
    jpeg: 'Picture',
    gif: 'Picture',
    svg: 'Picture',
    pdf: 'PDF',
    txt: 'Txt',
    py: 'Python',
    zip: 'Zip',
    go: 'Golang',
    c: 'C',
    cpp: 'CPP',
    js: 'JS',
    exe: 'Exe',
    apk: 'Apk',
    iso: 'ISO',
    pcap: 'Pcap'
  }

  return extensionMap[extension as keyof typeof extensionMap] || 'File'
}
