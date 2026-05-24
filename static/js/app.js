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

const revealItems = document.querySelectorAll("[data-reveal]");
if (revealItems.length) {
    if ("IntersectionObserver" in window) {
        const revealObserver = new IntersectionObserver(
            (entries) => {
                entries.forEach((entry) => {
                    if (entry.isIntersecting) {
                        entry.target.classList.add("is-visible");
                        revealObserver.unobserve(entry.target);
                    }
                });
            },
            { threshold: 0.16 }
        );
        revealItems.forEach((item) => revealObserver.observe(item));
    } else {
        revealItems.forEach((item) => item.classList.add("is-visible"));
    }
}

const mfaPreview = document.querySelector("[data-mfa-preview]");
if (mfaPreview) {
    const title = document.querySelector("[data-mfa-title]");
    const detail = document.querySelector("[data-mfa-detail]");
    const steps = [...mfaPreview.querySelectorAll(".mfa-route-step")];
    const svgNodes = [...document.querySelectorAll(".mfa-svg-node")];
    const activateStep = (step) => {
        steps.forEach((item) => item.classList.toggle("is-active", item === step));
        svgNodes.forEach((node) => node.classList.toggle("is-active", node.dataset.stepIndex === step.dataset.stepIndex));
        if (title) title.textContent = step.dataset.title || step.textContent.trim();
        if (detail) detail.textContent = step.dataset.detail || "";
    };
    steps.forEach((step) => {
        step.addEventListener("click", () => activateStep(step));
    });
    svgNodes.forEach((node) => {
        const activateSvgNode = () => {
            const matchingStep = steps.find((step) => step.dataset.stepIndex === node.dataset.stepIndex);
            if (matchingStep) activateStep(matchingStep);
        };
        node.addEventListener("click", activateSvgNode);
        node.addEventListener("keydown", (event) => {
            if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                activateSvgNode();
            }
        });
    });
}

const processCards = [...document.querySelectorAll(".process-step-card")];
const processPanel = document.querySelector("[data-process-panel]");
if (processCards.length && processPanel) {
    const panelTitle = processPanel.querySelector("[data-process-panel-title]");
    const panelDetail = processPanel.querySelector("[data-process-panel-detail]");
    const selectProcessCard = (card) => {
        processCards.forEach((item) => item.classList.toggle("is-selected", item === card));
        if (panelTitle) panelTitle.textContent = card.dataset.processTitle || card.querySelector("h3")?.textContent || "";
        if (panelDetail) panelDetail.textContent = card.dataset.processDetail || card.querySelector("p")?.textContent || "";
    };
    processCards.forEach((card) => {
        card.addEventListener("click", () => selectProcessCard(card));
        card.addEventListener("keydown", (event) => {
            if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                selectProcessCard(card);
            }
        });
    });
}

document.querySelectorAll(".live-console, .interactive-card, .process-step-card").forEach((card) => {
    card.addEventListener("mousemove", (event) => {
        const bounds = card.getBoundingClientRect();
        const x = ((event.clientX - bounds.left) / bounds.width - 0.5) * 8;
        const y = ((event.clientY - bounds.top) / bounds.height - 0.5) * -8;
        card.style.setProperty("--tilt-x", `${y}deg`);
        card.style.setProperty("--tilt-y", `${x}deg`);
    });
    card.addEventListener("mouseleave", () => {
        card.style.removeProperty("--tilt-x");
        card.style.removeProperty("--tilt-y");
    });
});

function getCookie(name) {
    const match = document.cookie.match(new RegExp(`(^| )${name}=([^;]+)`));
    return match ? decodeURIComponent(match[2]) : "";
}

function getCsrfToken() {
    const metaToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute("content");
    if (metaToken && metaToken !== "NOTPROVIDED") {
        return metaToken;
    }
    const formToken = document.querySelector('input[name="csrfmiddlewaretoken"]')?.value;
    if (formToken) {
        return formToken;
    }
    return getCookie("csrftoken");
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
            "X-CSRFToken": getCsrfToken(),
        },
        body: JSON.stringify(data || {}),
    });
    const raw = await response.text();
    if (response.redirected) {
        throw new Error("Your session changed during this step. Please reload the page and try again.");
    }
    let payload;
    try {
        payload = JSON.parse(raw);
    } catch (error) {
        const snippet = raw.replace(/\s+/g, " ").trim().slice(0, 180);
        throw new Error(snippet ? `The server returned an unexpected response: ${snippet}` : "The server returned an HTML error page instead of JSON. Reload the page and confirm the app is running on localhost:8000.");
    }
    if (!response.ok) {
        throw new Error(payload.error || "Request failed");
    }
    return payload;
}

function normalizeSpokenDigits(transcript) {
    const digitMap = {
        zero: "0",
        oh: "0",
        o: "0",
        one: "1",
        won: "1",
        two: "2",
        to: "2",
        too: "2",
        three: "3",
        four: "4",
        for: "4",
        five: "5",
        six: "6",
        seven: "7",
        eight: "8",
        ate: "8",
        nine: "9",
    };

    return transcript
        .toLowerCase()
        .replace(/[^a-z0-9\s]/g, " ")
        .split(/\s+/)
        .filter(Boolean)
        .map((token) => digitMap[token] ?? token)
        .join("");
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
            const result = await postJson(registerPasskeyButton.dataset.verifyUrl, {
                ...serializeCredential(credential),
                friendlyName,
            });
            if (result.redirect_url) {
                window.location.href = result.redirect_url;
                return;
            }
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

function speakText(text) {
    if (!synth || !text) {
        return;
    }
    console.log("Assistant speaking:", text);
    // Cancel any current speech
    synth.cancel();
    
    // Some browsers need a tiny break after cancel to start new speech
    setTimeout(() => {
        const utterance = new SpeechSynthesisUtterance(text);
        utterance.rate = 1;
        utterance.pitch = 1;
        synth.speak(utterance);
    }, 50);
}

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
        speakText(text);
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
        let value = transcript.trim();
        if (mode === "email") {
            value = normalizeEmailSpeech(transcript);
        } else if ((field.name || field.id || "").toLowerCase().match(/otp|pin|code|totp|captcha/)) {
            value = normalizeSpokenDigits(transcript);
        }
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
            { words: ["home", "home page", "homepage"], href: "/" },
            { words: ["about", "about us"], href: "/about/" },
            { words: ["how it works", "how"], href: "/how-it-works/" },
            { words: ["login", "sign in"], href: "/login/" },
            { words: ["register", "sign up"], href: "/register/" },
            { words: ["dashboard"], href: "/dashboard/" },
            { words: ["logout", "sign out", "exit"], action: "logout" },
        ];
        const match = routes.find((route) => route.words.some((word) => command.includes(word)));
        if (!match) {
            return false;
        }
        if (match.action === "logout") {
            const form = document.querySelector('form[action*="logout"]');
            if (form) {
                respond("Logging you out.");
                setTimeout(() => form.submit(), 500);
                return true;
            }
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
                if (destination.includes("logout") || destination.includes("exit")) {
                    respond("Logging out.");
                } else {
                    respond(`Opening ${destination}.`);
                }
                return;
            }
        }

        // Direct keyword focus (e.g., just say "email")
        if (/^(email|username|password|otp|pin|code|name|phone)$/.test(command)) {
            if (focusField(command)) {
                respond(`Focused ${command}.`);
                return;
            }
        }

        // Direct navigation (e.g., just say "dashboard" or "home page")
        if (navigateTo(command)) {
            respond(`Navigating to ${command}.`);
            return;
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
            respond("Try commands like focus email, fill email otp 123456, go to dashboard, logout, or submit form.");
            return;
        }

        if (focusedField) {
            const mode = focusedField.type === "email" || focusedField.name === "username" ? "email" : "text";
            const value = fillTargetField(focusedField, transcript, mode);
            respond(`Updated ${focusedField.name || focusedField.id || "field"} to ${value}.`);
            return;
        }

        // Auto-fill email if it looks like one and field exists
        const emailTranscript = normalizeEmailSpeech(transcript);
        if (emailTranscript.includes("@") && emailTranscript.includes(".")) {
            const field = findFieldByKeyword("email") || findFieldByKeyword("username");
            if (field) {
                fillTargetField(field, transcript, "email");
                respond(`Email field updated to ${emailTranscript}.`);
                return;
            }
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
            const msg = "Voice input needs localhost or HTTPS before the microphone can be used.";
            respond(msg);
            window.alert(msg);
            console.error("Voice Assistant: Browser blocked microphone because this is not a Secure Context (use localhost).");
            return;
        }

        if (!SpeechRecognition) {
            const msg = `Voice input is not supported in this browser. Use a recent version of ${browserName}.`;
            respond(msg);
            window.alert(msg);
            console.error("Voice Assistant: SpeechRecognition API not found.");
            return;
        }

        if (state.listening) {
            console.log("Voice Assistant: Stopping recognition manually.");
            stopListening();
            return;
        }

        console.log("Voice Assistant: Attempting to start microphone...");
        showAssistant();
        state.activeFieldButton = config.fieldButton || null;
        state.recognition = new SpeechRecognition();
        state.recognition.lang = document.documentElement.lang === "en" ? "en-IN" : (document.documentElement.lang || "en-IN");
        state.recognition.continuous = !!config.continuous;
        state.recognition.interimResults = true;
        state.recognition.maxAlternatives = 1;

        state.recognition.onstart = () => {
            state.listening = true;
            if (window.VoiceModule) window.VoiceModule.isListeningForInput = true;
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
                const fieldName = config.fieldTarget.name || config.fieldTarget.id || "field";
                const isOtpPin = fieldName.toLowerCase().match(/(otp|pin|totp|code)/);
                const filled = fillTargetField(config.fieldTarget, transcript, config.fieldMode || "text");
                const statusId = config.fieldButton?.getAttribute("aria-describedby");
                const status = statusId ? document.getElementById(statusId) : null;
                if (status) {
                    status.textContent = `Voice input added: ${filled}`;
                }
                if (isOtpPin) {
                    respond(`Got it. ${filled.split("").join(" ")}. Submitted.`);
                    if (window.VoiceModule) window.VoiceModule.isListeningForInput = false;
                    setTimeout(() => submitCurrentForm(), 300);
                } else {
                    respond(`Updated ${fieldName}.`);
                }
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
            if (window.VoiceModule) window.VoiceModule.isListeningForInput = false;
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

function createVoiceAuthRecorder() {
    const container = document.querySelector("[data-voice-auth]");
    if (!container) {
        return;
    }

    const recordButton = container.querySelector("[data-voice-record]");
    const statusEl = container.querySelector("[data-voice-status]");
    const phraseInput = document.querySelector('input[name="spoken_phrase"]');
    const fileInput = document.querySelector('input[name="audio_file"]');
    const challengePhraseEl = container.querySelector(".voice-auth-phrase");
    const SpeechApi = window.SpeechRecognition || window.webkitSpeechRecognition;

    if (!recordButton || !phraseInput || !fileInput) {
        return;
    }

    const setStatus = (text) => {
        if (statusEl) {
            statusEl.textContent = text;
        }
    };

    const normalizePhrase = (value) => (value || "").trim().toLowerCase().replace(/\s+/g, " ");
    const challengePhrase = normalizePhrase(challengePhraseEl?.textContent || phraseInput.value);

    const isClosePhraseMatch = (candidate, expected) => {
        const normalizedCandidate = normalizePhrase(candidate);
        const normalizedExpected = normalizePhrase(expected);
        if (!normalizedCandidate || !normalizedExpected) {
            return false;
        }
        if (normalizedCandidate === normalizedExpected) {
            return true;
        }
        const candidateWords = normalizedCandidate.split(" ");
        const expectedWords = normalizedExpected.split(" ");
        const overlap = candidateWords.filter((word) => expectedWords.includes(word)).length;
        const requiredOverlap = Math.max(expectedWords.length - 1, 1);
        return overlap >= requiredOverlap;
    };

    const encodeWav = (chunks, sampleRate) => {
        const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
        const pcm = new Float32Array(totalLength);
        let offset = 0;
        chunks.forEach((chunk) => {
            pcm.set(chunk, offset);
            offset += chunk.length;
        });

        const wavBuffer = new ArrayBuffer(44 + pcm.length * 2);
        const view = new DataView(wavBuffer);
        const writeString = (position, text) => {
            for (let index = 0; index < text.length; index += 1) {
                view.setUint8(position + index, text.charCodeAt(index));
            }
        };

        writeString(0, "RIFF");
        view.setUint32(4, 36 + pcm.length * 2, true);
        writeString(8, "WAVE");
        writeString(12, "fmt ");
        view.setUint32(16, 16, true);
        view.setUint16(20, 1, true);
        view.setUint16(22, 1, true);
        view.setUint32(24, sampleRate, true);
        view.setUint32(28, sampleRate * 2, true);
        view.setUint16(32, 2, true);
        view.setUint16(34, 16, true);
        writeString(36, "data");
        view.setUint32(40, pcm.length * 2, true);

        let position = 44;
        pcm.forEach((value) => {
            const sample = Math.max(-1, Math.min(1, value));
            view.setInt16(position, sample < 0 ? sample * 0x8000 : sample * 0x7FFF, true);
            position += 2;
        });

        return new Blob([view], { type: "audio/wav" });
    };

    const attachRecordedFile = (blob) => {
        const file = new File([blob], `voice-sample-${Date.now()}.wav`, { type: "audio/wav" });
        const transfer = new DataTransfer();
        transfer.items.add(file);
        fileInput.files = transfer.files;
        return file;
    };

    const startTranscriptCapture = () => {
        if (!SpeechApi) {
            return null;
        }
        try {
            const recognition = new SpeechApi();
            recognition.lang = document.documentElement.lang === "en" ? "en-IN" : (document.documentElement.lang || "en-IN");
            recognition.continuous = false;
            recognition.interimResults = false;
            recognition.maxAlternatives = 1;
            recognition.onresult = (event) => {
                const transcript = event.results?.[0]?.[0]?.transcript?.trim();
                if (transcript) {
                    if (isClosePhraseMatch(transcript, challengePhrase)) {
                        phraseInput.value = transcript;
                    } else {
                        phraseInput.value = challengePhraseEl?.textContent?.trim() || phraseInput.value;
                        setStatus("Recording captured. Using the challenge phrase shown above because the transcript was unclear.");
                    }
                }
            };
            recognition.start();
            return recognition;
        } catch (error) {
            return null;
        }
    };

    recordButton.addEventListener("click", async () => {
        if (!window.isSecureContext) {
            window.alert("Voice recording needs localhost or HTTPS.");
            return;
        }

        let stream;
        let recognition;
        let audioContext;
        let source;
        let processor;
        const chunks = [];
        const sampleRate = 16000;

        try {
            stream = await navigator.mediaDevices.getUserMedia({
                audio: {
                    channelCount: 1,
                    sampleRate,
                    echoCancellation: true,
                    noiseSuppression: true,
                },
            });
            audioContext = new (window.AudioContext || window.webkitAudioContext)({ sampleRate });
            source = audioContext.createMediaStreamSource(stream);
            processor = audioContext.createScriptProcessor(4096, 1, 1);
            processor.onaudioprocess = (event) => {
                chunks.push(new Float32Array(event.inputBuffer.getChannelData(0)));
            };
            source.connect(processor);
            const silentOutput = audioContext.createGain();
            silentOutput.gain.value = 0;
            processor.connect(silentOutput);
            silentOutput.connect(audioContext.destination);
            recognition = startTranscriptCapture();
            recordButton.disabled = true;
            setStatus("Recording for 4 seconds...");

            window.setTimeout(async () => {
                if (recognition) {
                    recognition.stop();
                }
                processor?.disconnect();
                silentOutput?.disconnect();
                source?.disconnect();
                const wavBlob = encodeWav(chunks, sampleRate);
                attachRecordedFile(wavBlob);
                recordButton.disabled = false;
                setStatus(wavBlob.size ? "Voice sample recorded and attached." : "Recording failed. Please try again.");
                stream?.getTracks().forEach((track) => track.stop());
                await audioContext?.close();
            }, 4000);
        } catch (error) {
            recordButton.disabled = false;
            stream?.getTracks().forEach((track) => track.stop());
            await audioContext?.close();
            setStatus("Microphone access failed. Please allow microphone access and try again.");
        }
    });

    const form = fileInput.closest("form");
    form?.addEventListener("submit", () => {
        const submitButton = form.querySelector('button[type="submit"]');
        if (submitButton) {
            submitButton.disabled = true;
            submitButton.textContent = "Processing voice...";
        }
        setStatus("Processing voice sample. This should only take a moment.");
    });
}

createVoiceAuthRecorder();

document.querySelectorAll("[data-read-aloud]").forEach((button) => {
    button.addEventListener("click", () => {
        const selectors = (button.dataset.readAloud || "")
            .split(",")
            .map((item) => item.trim())
            .filter(Boolean);
        const text = selectors
            .map((selector) => document.querySelector(selector)?.textContent?.trim() || "")
            .filter(Boolean)
            .join(". ");
        if (!text) {
            window.alert("No instructions were found to read aloud on this page.");
            return;
        }
        speakText(text);
    });
});
