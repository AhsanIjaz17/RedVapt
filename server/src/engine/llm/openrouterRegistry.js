import axios from "axios";

// Default fallback list in case the API doesn't respond or OpenRouter changes their API
const FALLBACK_FREE_MODELS = [
    "meta-llama/llama-3.3-70b-instruct:free",
    "meta-llama/llama-3.1-8b-instruct:free",
    "google/gemini-2.0-flash-exp:free",
    "mistralai/mistral-7b-instruct:free",
    "qwen/qwen3-8b:free",
];

let lastSuccessfulModel = null;
let cachedFreeModels = null;
let cacheTimestamp = 0;
const CACHE_TTL = 3600 * 1000; // 1 hour

export async function fetchOpenRouterFreeModels(minContext = 0) {
    // Return cached models if still valid
    if (cachedFreeModels && (Date.now() - cacheTimestamp) < CACHE_TTL) {
        return cachedFreeModels;
    }

    try {
        const response = await axios.get("https://openrouter.ai/api/v1/models", { timeout: 10000 });
        const allModels = response.data?.data || [];

        // Filter: price == 0 and meets context limit
        const freeModels = allModels.filter(m => {
            const isFree = m.pricing?.prompt === "0" && m.pricing?.completion === "0";
            const meetsContext = minContext ? (m.context_length >= minContext) : true;
            return isFree && meetsContext && m.id.endsWith(":free");
        }).map(m => m.id);

        if (freeModels.length > 0) {
            cachedFreeModels = freeModels;
            cacheTimestamp = Date.now();
            return freeModels;
        }
    } catch (err) {
        console.warn(`[OpenRouterRegistry] Failed to fetch live models: ${err.message}. Using fallback.`);
    }

    // Fallback if API fails
    return FALLBACK_FREE_MODELS;
}

export function getLastSuccessfulModel() {
    return lastSuccessfulModel;
}

export function setLastSuccessfulModel(modelId) {
    lastSuccessfulModel = modelId;
}
