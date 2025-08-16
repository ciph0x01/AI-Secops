**AI Red Teaming** terms, detailing:

1. **What kind of information it gives us**
2. **Why it matters for testing**
3. **Which engagement type (Black Box / White Box / Grey Box) it’s best to ask for**

---

## **1. AI Model Assessment**

| Item                | What It Tells Us                                                                                  | Why It Matters in Red Teaming                                                                                                                                                                            | Engagement Type                                                                 |
| ------------------- | ------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| **Model Type**      | Whether it’s an LLM (like GPT), multimodal (text + image), or niche AI (e.g., sentiment analysis) | Different model types have different attack surfaces: multimodal might allow image-based prompt injections, LLMs have jailbreak vulnerabilities, specialized AIs may have narrower but deeper weaknesses | **Black Box** (observed via behaviour) + **White Box** (for exact type/version) |
| **Architecture**    | Transformer, RNN, parameter size, training style                                                  | Architecture impacts exploit feasibility (e.g., tokenization quirks in Transformers can be abused for token-fragment attacks)                                                                            | **White Box** (needs insider disclosure)                                        |
| **Capabilities**    | Functions it can perform-reasoning, code writing, multimodal parsing                              | Determines which attack chains are possible: reasoning models are more susceptible to chain-of-trust poisoning; code generation can be abused for malicious payload crafting                             | **Black Box** for broad testing, **White Box** for edge-case exploration        |
| **Safety Training** | Whether RLHF, content filters, or alignment models are used                                       | Helps find safety bypass vectors-if RLHF is in place, we test for indirect prompt injection; if filters are server-side, test with obfuscation                                                           | **White Box** (detailed info), **Grey Box** (general approach info)             |

---

## **2. Interface Analysis**

| Item                   | What It Tells Us                                                        | Why It Matters in Red Teaming                                                                                           | Engagement Type                                                                 |
| ---------------------- | ----------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| **Chat Platforms**     | Where the model is deployed-web, mobile, API                            | Determines delivery vectors for payloads (e.g., mobile app may allow voice-based injection)                             | **Black Box** (can be inferred), **White Box** (internal deployment details)    |
| **Input Methods**      | Accepted formats-text, voice, images, docs                              | Broadens attack surface: doc parsing may allow embedded malicious instructions, images can carry steganographic prompts | **Black Box** (through experimentation)                                         |
| **Session Management** | How conversation context is stored and reused                           | Enables session poisoning attacks, context leakage testing, or long-term instruction persistence exploitation           | **Grey Box** (basic retention info) or **White Box** (technical implementation) |
| **User Controls**      | What parameters can be adjusted-temperature, max tokens, system prompts | Some controls can weaken safety (low temperature may be deterministic for prompt chaining)                              | **Black Box** (user interface observation)                                      |

---

## **3. API Endpoints**

| Item               | What It Tells Us                                          | Why It Matters in Red Teaming                                                                                  | Engagement Type               |
| ------------------ | --------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | ----------------------------- |
| **Core Functions** | API capabilities-chat completion, embeddings, fine-tuning | Each function has unique vulnerabilities: fine-tuning endpoints can be poisoned, embeddings can be manipulated | **White Box** (documentation) |
| **Authentication** | Mechanism-API keys, OAuth, JWT                            | Helps assess attack feasibility (e.g., key exfiltration risk, token replay)                                    | **White Box**                 |
| **Rate Limiting**  | Limits per user/token                                     | Dictates how aggressive we can be without tripping defenses, helps simulate DoS vectors                        | **White Box**                 |
| **Integration**    | Links to webhooks, SDKs, third-party systems              | Increases supply chain attack surface (malicious webhook injection)                                            | **White Box**                 |

---

### **When to Ask**

* **Black Box**: If the goal is “pure attacker simulation,” ask for minimal details-only public-facing behaviour matters.
* **White Box**: For safety-critical systems or deeper root-cause analysis, request detailed documentation about architecture, training, APIs, and safety layers.
* **Grey Box**: Most common in AI red teaming-request enough info to scope efficiently (e.g., model type, general deployment structure) without full internals.

