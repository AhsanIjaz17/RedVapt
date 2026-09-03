/**
 * toolRegistry.js — Tool Definition & Dispatch Registry
 *
 * Central registry for all tools available to the ReAct agent.
 * Each tool has: name, description, parameters (JSON Schema), execute(params).
 * The registry provides tool definitions to the LLM and dispatches execution.
 */

export class ToolRegistry {
    constructor() {
        /** @type {Map<string, { schema: object, execute: Function }>} */
        this.tools = new Map();
    }

    /**
     * Register a tool with its schema and executor function.
     * @param {string} name - Tool name (used by LLM to select)
     * @param {object} schema - JSON schema describing the tool
     * @param {Function} executeFn - async (params) => result
     */
    registerTool(name, schema, executeFn) {
        this.tools.set(name, { schema, execute: executeFn });
    }

    /**
     * Execute a registered tool by name.
     * @param {string} name - Tool name
     * @param {object} params - Parameters to pass
     * @returns {Promise<object>} - Tool execution result
     */
    async executeTool(name, params) {
        const tool = this.tools.get(name);
        if (!tool) {
            return { error: `Unknown tool: ${name}`, available: [...this.tools.keys()] };
        }

        const startTime = Date.now();
        try {
            const result = await tool.execute(params);
            return {
                success: true,
                tool: name,
                duration_ms: Date.now() - startTime,
                result,
            };
        } catch (err) {
            return {
                success: false,
                tool: name,
                duration_ms: Date.now() - startTime,
                error: err.message || String(err),
            };
        }
    }

    /**
     * Get all tool definitions formatted for LLM prompt context.
     * @returns {object[]} Array of tool schemas
     */
    getToolDefinitions() {
        const defs = [];
        for (const [name, { schema }] of this.tools) {
            defs.push({ name, ...schema });
        }
        return defs;
    }

    /**
     * Get tool names list.
     * @returns {string[]}
     */
    getToolNames() {
        return [...this.tools.keys()];
    }

    /**
     * Check if a tool exists.
     * @param {string} name
     * @returns {boolean}
     */
    hasTool(name) {
        return this.tools.has(name);
    }
}
