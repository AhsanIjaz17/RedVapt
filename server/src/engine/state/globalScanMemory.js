/**
 * globalScanMemory.js — AI continuity storage
 *
 * Preserves scan context, attempted payloads, and evidence so that
 * when OpenRouter switches models due to errors or timeouts,
 * the fresh AI context still remembers what has happened.
 */

export class GlobalScanMemory {
    constructor() {
        this.history = []; // Array of interaction cycles
        this.notes = new Set(); // Global deductions
    }

    recordCycle(inputStr, actionObj, resultStr) {
        this.history.push({
            timestamp: Date.now(),
            input: inputStr,
            action: actionObj,
            result: resultStr,
        });
    }

    addNote(note) {
        this.notes.add(note);
    }

    getSnapshot(maxHistoryItems = 5) {
        return JSON.stringify({
            notes: Array.from(this.notes),
            recentHistory: this.history.slice(-maxHistoryItems)
        });
    }

    exportState() {
        return {
            historyLength: this.history.length,
            notes: Array.from(this.notes)
        };
    }

    importState(stateData) {
        if (!stateData) return;
        this.history = stateData.history || [];
        this.notes = new Set(stateData.notes || []);
    }
}

export const scanMemory = new GlobalScanMemory();
