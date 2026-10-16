/** One line to stdout with a UTC timestamp. Never pass a token or a raw error message here. */
export function log(message: string): void {
  console.log(`${new Date().toISOString()} ${message}`)
}
