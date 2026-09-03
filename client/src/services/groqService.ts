
import Groq from "groq-sdk";

export class GroqService {
  private static instance: GroqService;
  private groq: Groq;

  private constructor() {
    this.groq = new Groq({
      apiKey: import.meta.env.VITE_GROQ_API_KEY || process.env.GROQ_API_KEY,
      dangerouslyAllowBrowser: true // Ideally use a backend proxy, but for this demo/local setup it's fine
    });
  }

  public static getInstance(): GroqService {
    if (!GroqService.instance) {
      GroqService.instance = new GroqService();
    }
    return GroqService.instance;
  }

  public async getSecurityAnalysis(target: string, findings: string[]): Promise<string> {
    try {
      const response = await this.groq.chat.completions.create({
        model: import.meta.env.VITE_GROQ_MODEL || process.env.GROQ_MODEL || "llama-3.1-8b-instant",
        messages: [
          {
            role: "system",
            content: "You are a RedVapt AI Penetration Testing Agent. Analyze the provided findings and provide a concise security summary and prioritised next steps for exploitation testing. Keep your answers technical, ethical, and structured for professional penetration testers."
          },
          {
            role: "user",
            content: `Analyze these findings for target ${target}: ${findings.join(', ')}`
          }
        ],
        temperature: 0.7,
      });
      return response.choices[0]?.message?.content || "No analysis available.";
    } catch (error) {
      console.error("Groq API Error:", error);
      return "An error occurred during AI analysis.";
    }
  }

  public async chat(message: string): Promise<string> {
    try {
      const response = await this.groq.chat.completions.create({
        model: import.meta.env.VITE_GROQ_MODEL || process.env.GROQ_MODEL || "llama-3.1-8b-instant",
        messages: [
          {
            role: "system",
            content: "You are the RedVapt AI assistant. You help users navigate the platform, explain vulnerability findings, and provide remediation advice based on industry standards like OWASP. Use a professional, secure-coding oriented tone."
          },
          {
            role: "user",
            content: message
          }
        ],
        temperature: 0.8,
      });
      return response.choices[0]?.message?.content || "I'm sorry, I couldn't process that request.";
    } catch (error) {
      console.error("Chat Error:", error);
      return "Error communicating with AI agent.";
    }
  }
}
