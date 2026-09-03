/**
 * scanManager.js
 * 
 * Simple tracker of active scans by workspace ID or scan ID.
 * Maps identifiers to their respective AbortControllers so they can be
 * forcefully stopped if the user cancels them from the UI.
 */

// activeScans: Map<string, AbortController>
const activeScans = new Map();

/**
 * Generates a consistent key for a given workspace and target.
 * @param {string} workspaceId 
 * @param {string} target 
 * @returns {string}
 */
export function getScanKey(workspaceId, target) {
    return `${workspaceId}_${target}`;
}

/**
 * Registers a new active scan under a specific key.
 * @param {string} key 
 * @param {AbortController} controller 
 */
export function registerScan(key, controller) {
    activeScans.set(key, controller);
}

/**
 * Unregisters a scan (e.g. when scan finishes successfully).
 * @param {string} key 
 */
export function unregisterScan(key) {
    activeScans.delete(key);
}

/**
 * Forcefully aborts a registered scan if it exists, and unregisters it.
 * @param {string} key 
 * @returns {boolean} True if the scan existed and was aborted.
 */
export function abortScan(key) {
    const controller = activeScans.get(key);
    if (controller) {
        // Broadcast the abort signal to all connected child_process / LLM calls
        controller.abort();
        activeScans.delete(key);
        return true;
    }
    return false;
}

/** Live scans currently running in this process (not stale DB rows). */
export function getActiveScanCountForWorkspace(workspaceId) {
    if (!workspaceId) return 0;
    const prefix = `${workspaceId}_`;
    let count = 0;
    for (const key of activeScans.keys()) {
        if (key.startsWith(prefix)) count += 1;
    }
    return count;
}
