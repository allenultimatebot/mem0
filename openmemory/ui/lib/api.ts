export const openMemoryApiUrl = (path: string): string => {
  const normalizedPath = path.replace(/^\/+|\/+$/g, "")
  return `/api/openmemory/${normalizedPath}`
}
