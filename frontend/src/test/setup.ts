import '@testing-library/jest-dom/vitest'

import { afterEach, vi } from 'vitest'

import { clearAccessToken } from '../api/client'

// Use the test browser's Storage, even when Node exposes its own experimental
// Web Storage globals. Tests must observe browser writes, not host storage.
const testBrowser = (globalThis as unknown as { jsdom: { window: Window } }).jsdom.window
vi.stubGlobal('localStorage', testBrowser.localStorage)
vi.stubGlobal('sessionStorage', testBrowser.sessionStorage)

// Ensure no test can leak an access token into another test.
afterEach(() => {
  clearAccessToken()
  testBrowser.localStorage.clear()
  testBrowser.sessionStorage.clear()
})
