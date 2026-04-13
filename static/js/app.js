document.querySelectorAll(".flash").forEach((flash) => {
    setTimeout(() => {
        flash.style.opacity = "0";
        flash.style.transition = "opacity 300ms ease";
    }, 4500);
});

const resendSeconds = document.querySelector("#resend-seconds");
if (resendSeconds) {
    const button = resendSeconds.closest("button");
    let remaining = Number.parseInt(resendSeconds.textContent, 10);
    const timer = window.setInterval(() => {
        remaining -= 1;
        if (remaining <= 0) {
            window.clearInterval(timer);
            if (button) {
                button.disabled = false;
                button.textContent = "Resend OTP";
            }
            return;
        }
        resendSeconds.textContent = String(remaining);
    }, 1000);
}

document.querySelectorAll('a[href*="#"]').forEach((anchor) => {
    anchor.addEventListener("click", (event) => {
        const href = anchor.getAttribute("href");
        if (!href || !href.includes("#")) {
            return;
        }
        const hash = href.split("#")[1];
        if (!hash || anchor.pathname !== window.location.pathname) {
            return;
        }
        const target = document.getElementById(hash);
        if (!target) {
            return;
        }
        event.preventDefault();
        target.scrollIntoView({ behavior: "smooth", block: "start" });
        window.history.replaceState(null, "", `#${hash}`);
    });
});

function getCookie(name) {
    const match = document.cookie.match(new RegExp(`(^| )${name}=([^;]+)`));
    return match ? decodeURIComponent(match[2]) : "";
}

function base64UrlToBuffer(base64url) {
    const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
    const binary = window.atob(padded);
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function bufferToBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    bytes.forEach((byte) => {
        binary += String.fromCharCode(byte);
    });
    return window.btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function normalizeRegistrationOptions(options) {
    return {
        ...options,
        challenge: base64UrlToBuffer(options.challenge),
        user: {
            ...options.user,
            id: base64UrlToBuffer(options.user.id),
        },
        excludeCredentials: (options.excludeCredentials || []).map((item) => ({
            ...item,
            id: base64UrlToBuffer(item.id),
        })),
    };
}

function normalizeAuthenticationOptions(options) {
    return {
        ...options,
        challenge: base64UrlToBuffer(options.challenge),
        allowCredentials: (options.allowCredentials || []).map((item) => ({
            ...item,
            id: base64UrlToBuffer(item.id),
        })),
    };
}

function serializeCredential(credential) {
    if (!credential) {
        return null;
    }
    const response = credential.response || {};
    return {
        id: credential.id,
        rawId: bufferToBase64Url(credential.rawId),
        type: credential.type,
        response: {
            clientDataJSON: bufferToBase64Url(response.clientDataJSON),
            attestationObject: response.attestationObject ? bufferToBase64Url(response.attestationObject) : undefined,
            authenticatorData: response.authenticatorData ? bufferToBase64Url(response.authenticatorData) : undefined,
            signature: response.signature ? bufferToBase64Url(response.signature) : undefined,
            userHandle: response.userHandle ? bufferToBase64Url(response.userHandle) : undefined,
            transports: typeof response.getTransports === "function" ? response.getTransports() : [],
        },
    };
}

async function postJson(url, data) {
    const response = await fetch(url, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": getCookie("csrftoken"),
        },
        body: JSON.stringify(data || {}),
    });
    const payload = await response.json();
    if (!response.ok) {
        throw new Error(payload.error || "Request failed");
    }
    return payload;
}

const registerPasskeyButton = document.querySelector("#register-passkey-button");
if (registerPasskeyButton && window.PublicKeyCredential) {
    registerPasskeyButton.addEventListener("click", async () => {
        try {
            const options = await postJson(registerPasskeyButton.dataset.optionsUrl, {});
            const credential = await navigator.credentials.create({
                publicKey: normalizeRegistrationOptions(options),
            });
            const friendlyName = window.prompt("Name this biometric login", "Primary Face Login") || "Primary Face Login";
            await postJson(registerPasskeyButton.dataset.verifyUrl, {
                ...serializeCredential(credential),
                friendlyName,
            });
            window.location.reload();
        } catch (error) {
            window.alert(error.message);
        }
    });
}

const verifyPasskeyButton = document.querySelector("#verify-passkey-button");
if (verifyPasskeyButton && window.PublicKeyCredential) {
    verifyPasskeyButton.addEventListener("click", async () => {
        try {
            const options = await postJson(verifyPasskeyButton.dataset.optionsUrl, {});
            const credential = await navigator.credentials.get({
                publicKey: normalizeAuthenticationOptions(options),
            });
            const result = await postJson(verifyPasskeyButton.dataset.verifyUrl, serializeCredential(credential));
            window.location.href = result.redirect_url;
        } catch (error) {
            window.alert(error.message);
        }
    });
}

function normalizeEmailSpeech(transcript) {
    return transcript
        .toLowerCase()
        .trim()
        .replace(/\bat the rate\b/g, "@")
        .replace(/\bat\b/g, "@")
        .replace(/\bdot\b/g, ".")
        .replace(/\bunderscore\b/g, "_")
        .replace(/\bhyphen\b/g, "-")
        .replace(/\bdash\b/g, "-")
        .replace(/\bplus\b/g, "+")
        .replace(/\s+/g, "");
}

const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
const synth = window.speechSynthesis;
const assistant = document.querySelector("[data-voice-assistant]");

function setFieldValue(field, value) {
    field.focus();
    field.value = value;
    field.dispatchEvent(new Event("input", { bubbles: true }));
    field.dispatchEvent(new Event("change", { bubbles: true }));
}

function findFieldByKeyword(keyword) {
    const normalized = keyword.toLowerCase();
    const fields = Array.from(document.querySelectorAll("input, textarea, select"));
    return fields.find((field) => {
        const label = field.labels?.[0]?.textContent?.toLowerCase() || "";
        const placeholder = (field.getAttribute("placeholder") || "").toLowerCase();
        const name = (field.getAttribute("name") || "").toLowerCase();
        const id = (field.id || "").toLowerCase();
        const type = (field.getAttribute("type") || "").toLowerCase();
        return [label, placeholder, name, id, type].some((value) => value.includes(normalized));
    }) || null;
}

function findFormActionButton(words) {
    const buttons = Array.from(document.querySelectorAll('button, input[type="submit"], a.button, .link-button'));
    return buttons.find((item) => {
        const text = (item.textContent || item.value || "").toLowerCase().trim();
        return words.some((word) => text.includes(word));
    }) || null;
}

function createVoiceAssistant() {
    if (!assistant) {
        return;
    }

    const transcriptEl = assistant.querySelector("[data-voice-transcript]");
    const statusEl = assistant.querySelector("[data-voice-status]");
    const toggleButton = assistant.querySelector("[data-voice-toggle]");
    const speakToggleButton = assistant.querySelector("[data-voice-speak-toggle]");
    const openButton = document.querySelector("[data-voice-open]");
    const closeButton = assistant.querySelector("[data-voice-close]");
    const browserName = /Edg\//.test(window.navigator.userAgent) ? "Edge" : "Chrome";

    const state = {
        listening: false,
        voiceReplyEnabled: false,
        recognition: null,
        activeFieldButton: null,
        interimTranscript: "",
    };

    const setTranscript = (text) => {
        if (transcriptEl) {
            transcriptEl.textContent = text;
        }
    };

    const setStatus = (text) => {
        if (statusEl) {
            statusEl.textContent = text;
        }
    };

    const speak = (text) => {
        if (!state.voiceReplyEnabled || !synth) {
            return;
        }
        synth.cancel();
        const utterance = new SpeechSynthesisUtterance(text);
        utterance.rate = 1;
        utterance.pitch = 1;
        synth.speak(utterance);
    };

    const respond = (text) => {
        setStatus(text);
        speak(text);
    };

    const showAssistant = () => {
        assistant.classList.add("is-open");
    };

    const hideAssistant = () => {
        assistant.classList.remove("is-open");
        stopListening();
    };

    const updateVoiceReplyButton = () => {
        if (speakToggleButton) {
            speakToggleButton.textContent = state.voiceReplyEnabled ? "Voice Reply On" : "Voice Reply Off";
            speakToggleButton.classList.toggle("is-active", state.voiceReplyEnabled);
        }
    };

    const fillTargetField = (field, transcript, mode = "text") => {
        const value = mode === "email" ? normalizeEmailSpeech(transcript) : transcript.trim();
        setFieldValue(field, value);
        return value;
    };

    const focusField = (keyword) => {
        const field = findFieldByKeyword(keyword);
        if (!field) {
            return false;
        }
        field.focus();
        field.scrollIntoView({ behavior: "smooth", block: "center" });
        return true;
    };

    const navigateTo = (command) => {
        const routes = [
            { words: ["home"], href: "/" },
            { words: ["about"], href: "/about/" },
            { words: ["how it works", "how"], href: "/how-it-works/" },
            { words: ["login", "sign in"], href: "/login/" },
            { words: ["register", "sign up"], href: "/register/" },
            { words: ["dashboard"], href: "/dashboard/" },
        ];
        const match = routes.find((route) => route.words.some((word) => command.includes(word)));
        if (!match) {
            return false;
        }
        window.location.href = match.href;
        return true;
    };

    const submitCurrentForm = () => {
        const active = document.activeElement;
        const form = active?.form || document.querySelector("form");
        if (!form) {
            return false;
        }
        const submitButton = form.querySelector('button[type="submit"], input[type="submit"]');
        if (submitButton) {
            submitButton.click();
            return true;
        }
        form.requestSubmit?.();
        return true;
    };

    const readPageSummary = () => {
        const heading = document.querySelector("h2, h1");
        const paragraph = document.querySelector(".card p, .hero-copy p, .page-hero p, p");
        const text = [heading?.textContent, paragraph?.textContent].filter(Boolean).join(". ");
        if (text) {
            respond(text);
            return true;
        }
        return false;
    };

    function handleVoiceCommand(transcript) {
        const command = transcript.toLowerCase().trim();
        const focusedField = document.activeElement?.matches?.("input, textarea, select") ? document.activeElement : null;

        if (!command) {
            respond("I did not catch that. Please try again.");
            return;
        }

        if (/^(go to|open|navigate to)\s+/.test(command)) {
            const destination = command.replace(/^(go to|open|navigate to)\s+/, "");
            if (navigateTo(destination)) {
                respond(`Opening ${destination}.`);
                return;
            }
        }

        if (/^(focus|select)\s+/.test(command)) {
            const keyword = command.replace(/^(focus|select)\s+/, "");
            if (focusField(keyword)) {
                respond(`Focused ${keyword}.`);
                return;
            }
        }

        if (/^(fill|set|type)\s+/.test(command)) {
            const match = command.match(/^(fill|set|type)\s+([a-z0-9 _-]+?)\s+(?:with\s+)?(.+)$/);
            if (match) {
                const [, , fieldName, value] = match;
                const field = findFieldByKeyword(fieldName);
                if (field) {
                    const normalizedValue = fillTargetField(field, value, fieldName.includes("email") ? "email" : "text");
                    respond(`${fieldName} updated to ${normalizedValue}.`);
                    return;
                }
            }
        }

        if (/^(submit|continue|login|sign in|verify)( form)?$/.test(command)) {
            if (submitCurrentForm()) {
                respond("Submitting the form.");
                return;
            }
        }

        if (/^(scroll down|move down)$/.test(command)) {
            window.scrollBy({ top: 500, behavior: "smooth" });
            respond("Scrolling down.");
            return;
        }

        if (/^(scroll up|move up)$/.test(command)) {
            window.scrollBy({ top: -500, behavior: "smooth" });
            respond("Scrolling up.");
            return;
        }

        if (/^(read page|read this page|what is on this page)$/.test(command)) {
            if (readPageSummary()) {
                return;
            }
        }

        if (/^(help|what can i say)$/.test(command)) {
            respond("Try commands like focus email, fill email member at gmail dot com, go to login, or submit form.");
            return;
        }

        if (focusedField) {
            const mode = focusedField.type === "email" || focusedField.name === "username" ? "email" : "text";
            const value = fillTargetField(focusedField, transcript, mode);
            respond(`Updated ${focusedField.name || focusedField.id || "field"} to ${value}.`);
            return;
        }

        respond("I heard you, but I could not match that to a page action. Try saying help.");
    }

    function stopListening() {
        if (state.recognition && state.listening) {
            state.recognition.stop();
        }
    }

    function updateListeningUi() {
        if (!toggleButton) {
            return;
        }
        toggleButton.textContent = state.listening ? "Stop Voice" : "Start Voice";
        toggleButton.classList.toggle("is-listening", state.listening);
        if (state.activeFieldButton) {
            state.activeFieldButton.textContent = state.listening ? "Stop voice" : "Use voice";
            state.activeFieldButton.classList.toggle("is-listening", state.listening);
        }
    }

    function startListening(config = {}) {
        if (!window.isSecureContext) {
            respond("Voice input needs localhost or HTTPS before the microphone can be used.");
            return;
        }

        if (!SpeechRecognition) {
            respond(`Voice input is not supported in this browser. Use a recent version of ${browserName}.`);
            return;
        }

        if (state.listening) {
            stopListening();
            return;
        }

        showAssistant();
        state.activeFieldButton = config.fieldButton || null;
        state.recognition = new SpeechRecognition();
        state.recognition.lang = document.documentElement.lang === "en" ? "en-IN" : (document.documentElement.lang || "en-IN");
        state.recognition.continuous = !!config.continuous;
        state.recognition.interimResults = true;
        state.recognition.maxAlternatives = 1;

        state.recognition.onstart = () => {
            state.listening = true;
            updateListeningUi();
            setTranscript(config.mode === "field" ? "Listening for field input..." : "Listening for commands or dictation...");
            setStatus(config.mode === "field"
                ? "Speak now to fill the selected field."
                : "Voice assistant is listening. You can dictate, navigate, or say help.");
        };

        state.recognition.onresult = (event) => {
            let finalTranscript = "";
            let interimTranscript = "";
            for (let index = event.resultIndex; index < event.results.length; index += 1) {
                const chunk = event.results[index][0]?.transcript || "";
                if (event.results[index].isFinal) {
                    finalTranscript += chunk;
                } else {
                    interimTranscript += chunk;
                }
            }

            state.interimTranscript = interimTranscript.trim();
            const displayed = [finalTranscript.trim(), state.interimTranscript].filter(Boolean).join(" ");
            if (displayed) {
                setTranscript(displayed);
            }

            if (!finalTranscript.trim()) {
                return;
            }

            const transcript = finalTranscript.trim();
            if (config.mode === "field" && config.fieldTarget) {
                const filled = fillTargetField(config.fieldTarget, transcript, config.fieldMode || "text");
                const statusId = config.fieldButton?.getAttribute("aria-describedby");
                const status = statusId ? document.getElementById(statusId) : null;
                if (status) {
                    status.textContent = `Voice input added: ${filled}`;
                }
                respond(`Updated ${config.fieldTarget.name || config.fieldTarget.id || "field"}.`);
                stopListening();
                return;
            }

            handleVoiceCommand(transcript);
        };

        state.recognition.onnomatch = () => {
            respond("No clear speech match was detected. Try speaking a little slower.");
        };

        state.recognition.onerror = (event) => {
            const messages = {
                "audio-capture": "No microphone was found. Check your microphone and browser permissions.",
                "network": "Speech recognition service is unavailable right now. Try again in Chrome or Edge.",
                "no-speech": "I did not hear any speech. Try again and speak a little closer to the microphone.",
                "not-allowed": "Microphone permission was blocked. Allow microphone access and reload the page.",
                "service-not-allowed": "Speech recognition was blocked for this page. Try Chrome or Edge and allow microphone access.",
            };
            if (event.error !== "aborted") {
                respond(messages[event.error] || "Voice input could not start. Please try again.");
            }
        };

        state.recognition.onend = () => {
            state.listening = false;
            state.activeFieldButton = null;
            updateListeningUi();
            if (!state.interimTranscript) {
                setTranscript("Press Start Voice and begin speaking.");
            }
        };

        try {
            setStatus("Starting microphone...");
            state.recognition.start();
        } catch (error) {
            state.listening = false;
            updateListeningUi();
            respond("Voice input could not start in this browser session. Reload the page and try again.");
        }
    }

    openButton?.addEventListener("click", showAssistant);
    closeButton?.addEventListener("click", hideAssistant);
    toggleButton?.addEventListener("click", () => startListening({ continuous: true }));
    speakToggleButton?.addEventListener("click", () => {
        state.voiceReplyEnabled = !state.voiceReplyEnabled;
        updateVoiceReplyButton();
        respond(state.voiceReplyEnabled ? "Voice reply is now on." : "Voice reply is now off.");
    });

    updateVoiceReplyButton();

    document.querySelectorAll("[data-voice-target]").forEach((button) => {
        const target = document.getElementById(button.dataset.voiceTarget);
        const statusId = button.getAttribute("aria-describedby");
        const status = statusId ? document.getElementById(statusId) : null;

        if (!target) {
            return;
        }

        if (!window.isSecureContext || !SpeechRecognition) {
            button.disabled = true;
            if (status) {
                status.textContent = !window.isSecureContext
                    ? "Voice input needs localhost or HTTPS before it can start."
                    : `Voice input is not supported in this browser. Use ${browserName}.`;
            }
            return;
        }

        button.addEventListener("click", () => {
            startListening({
                mode: "field",
                fieldTarget: target,
                fieldMode: button.dataset.voiceMode || "text",
                fieldButton: button,
            });
        });
    });
}

createVoiceAssistant();
