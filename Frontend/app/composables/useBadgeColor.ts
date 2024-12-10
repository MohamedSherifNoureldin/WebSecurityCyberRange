export const useBadgeColor = (name: string) => {
  switch (name) {
    case 'Web Exploitation':
      return 'sky'
    case 'Forensics':
      return 'teal'
    case 'Cryptography':
      return 'red'
    case 'Reverse Engineering':
      return 'fuchsia'
    case 'Miscellaneous':
      return 'lime'
    case 'Network Security':
      return 'yellow'
    case 'Binary Exploitation':
      return 'orange'
    case 'Steganography':
      return 'purple'
    case 'Warmup':
      return 'pink'
    default:
      return 'primary'
  }
}
