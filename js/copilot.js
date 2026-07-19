import { agentStageData } from "./data.js";

function chatEl(id) {
    return document.getElementById(id);
}
function addChatMessage(role, text) {
    const wrap = chatEl("chatMessages");
    const div = document.createElement("div");
    div.className = "chat-msg " + role;
    const tag = document.createElement("span");
    tag.className = "chat-msg-tag";
    tag.textContent = role === "user" ? "You" : "Aegis";
    div.appendChild(tag);
    div.appendChild(document.createTextNode(text));
    wrap.appendChild(div);
    wrap.scrollTop = wrap.scrollHeight;
    return div;
}
function chatReply(question) {
    const q = question.toLowerCase();
    const order = [
        [
            "threat-intelligence",
            [
                "threat intel",
                "indicator",
                "ioc",
                "hash",
                "domain",
                "malware family",
                "provider",
            ],
        ],
        [
            "triage",
            [
                "triage",
                "severity",
                "confidence",
                "classification",
                "isolat",
                "approval",
            ],
        ],
        [
            "investigation",
            ["investigat", "mitre", "root cause", "true positive", "lateral"],
        ],
        ["reporting", ["report", "export", "sign-off", "recommend"]],
        [
            "parsing",
            ["parsing", "parse", "normalis", "normaliz", "raw event", "field"],
        ],
    ];
    for (const pair of order) {
        if (pair[1].some((w) => q.includes(w)))
            return agentStageData[pair[0]].ai.text;
    }
    return `I can answer questions about any completed agent stage for ${chatEl("chatScope").textContent} — try asking about parsing, triage, Threat Intelligence Enrichment, investigation or reporting.`;
}
function handleChatSubmit(question) {
    const text = (question || "").trim();
    if (!text) return;
    addChatMessage("user", text);
    chatEl("chatInput").value = "";
    const wrap = chatEl("chatMessages");
    const typing = document.createElement("div");
    typing.className = "chat-typing";
    typing.textContent = "Aegis is typing…";
    wrap.appendChild(typing);
    wrap.scrollTop = wrap.scrollHeight;
    setTimeout(() => {
        typing.remove();
        addChatMessage("bot", chatReply(text));
    }, 650);
}
function resetChatForCase(ticket, title) {
    chatEl("chatScope").textContent = ticket;
    chatEl("chatMessages").innerHTML = "";
    addChatMessage(
        "bot",
        `I'm tracking ${ticket}${title ? " — " + title : ""} across every agent stage, including Threat Intelligence Enrichment. Ask me about parsing, triage, Threat Intelligence Enrichment, investigation or reporting.`,
    );
}
chatEl("chatForm").addEventListener("submit", (e) => {
    e.preventDefault();
    handleChatSubmit(chatEl("chatInput").value);
});
chatEl("chatSuggestions").addEventListener("click", (event) => {
    const button = event.target.closest("button[data-ask]");
    if (button) handleChatSubmit(button.dataset.ask);
});

export function initialiseCopilot() {
    // Copilot listeners are registered once when this module loads.
}

const investigationPrompts = {
    overview: [
        "Summarise investigation",
        "Explain key findings",
        "What requires analyst attention?",
    ],
    timeline: [
        "Explain this event",
        "Summarise the incident sequence",
        "What happened before this event?",
        "What happened after this event?",
    ],
    mitre: [
        "Explain this technique",
        "Why was this technique mapped?",
        "Show supporting evidence",
        "Which tactics may be missing?",
    ],
    entities: [
        "Explain this entity",
        "Why are these nodes connected?",
        "Show the highest-risk path",
        "Which entity is most important?",
    ],
    evidence: [
        "Summarise selected evidence",
        "Validate this indicator",
        "Show related evidence",
    ],
    activity: [
        "Summarise analyst activity",
        "What action happened most recently?",
        "Which decisions are still pending?",
    ],
};

export function updateInvestigationCopilotContext(tab, selectedLabel = "") {
    const suggestions = chatEl("chatSuggestions");
    const prompts = investigationPrompts[tab] ?? investigationPrompts.overview;

    suggestions.innerHTML = "";
    prompts.forEach((prompt) => {
        const button = document.createElement("button");
        button.type = "button";
        button.dataset.ask = selectedLabel
            ? `${prompt} Context: ${selectedLabel}`
            : prompt;
        button.textContent = prompt;
        suggestions.appendChild(button);
    });
}

export { resetChatForCase };
