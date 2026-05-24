document.addEventListener('DOMContentLoaded', () => {
    const voiceModule = {
        isListeningForInput: false,
        enableAutoVoiceForOtpPin: true,

        init() {
            this.detectPageContext();
            this.setupAutoVoiceInput();
            this.setupFeedbackListeners();
            this.enableVoiceReplyAutomatically();
        },

        detectPageContext() {
            const pathName = window.location.pathname.toLowerCase();
            const detectedContext = {
                isLoginPage: pathName.includes('login'),
                isRegisterPage: pathName.includes('register'),
                isOtpPage: pathName.includes('verify-otp') || pathName.includes('otp'),
                isPinPage: pathName.includes('verify-pin') || pathName.includes('pin'),
                isTotpPage: pathName.includes('verify-totp') || pathName.includes('totp'),
                isCaptchaPage: pathName.includes('verify-captcha') || pathName.includes('captcha'),
                isImagePage: pathName.includes('verify-image') || pathName.includes('image'),
                isDashboard: pathName.includes('dashboard'),
                isQuestion: pathName.includes('verify-question') || pathName.includes('question'),
            };
            this.context = detectedContext;
            return detectedContext;
        },

        setupAutoVoiceInput() {
            if (this.context.isOtpPage || this.context.isTotpPage || this.context.isPinPage) {
                setTimeout(() => {
                    const voiceToggle = document.querySelector('[data-voice-toggle]');
                    const voiceSpeakToggle = document.querySelector('[data-voice-speak-toggle]');
                    
                    if (voiceSpeakToggle && !voiceSpeakToggle.classList.contains('is-active')) {
                        voiceSpeakToggle.click();
                    }

                    const otpField = document.querySelector('input[name="otp"], input[name="pin"], input[name="code"]');
                    if (otpField && voiceToggle) {
                        const fieldLabel = otpField.labels?.[0]?.textContent || otpField.name || 'code';
                        const message = `Please enter your ${fieldLabel}. You can speak the digits or use voice commands.`;
                        const statusEl = document.querySelector('[data-voice-status]');
                        if (statusEl) {
                            statusEl.textContent = message;
                        }
                    }
                }, 800);
            }
        },

        enableVoiceReplyAutomatically() {
            const speakToggleBtn = document.querySelector('[data-voice-speak-toggle]');
            if (speakToggleBtn && !speakToggleBtn.classList.contains('is-active')) {
                const turnOnBtn = speakToggleBtn;
                if (turnOnBtn && !localStorage.getItem('voiceReplyEnabled')) {
                    setTimeout(() => {
                        turnOnBtn.click();
                        localStorage.setItem('voiceReplyEnabled', 'true');
                    }, 1000);
                }
            }
        },

        setupFeedbackListeners() {
            let hasAnnounced = false;
            document.addEventListener('submit', (e) => {
                const form = e.target;
                // If Voice Assistant is already handling this (app.js), let it speak instead
                if (window.VoiceModule?.isListeningForInput) return;

                if (form && !hasAnnounced) {
                    hasAnnounced = true;
                    const submitBtn = form.querySelector('button[type="submit"]');
                    const message = submitBtn?.textContent || 'Form submitted';
                    if (message.toLowerCase().includes('verify') || message.toLowerCase().includes('login') || message.toLowerCase().includes('submit')) {
                        this.speakFeedback('Processing your request. Please wait.');
                    }
                    // Reset flag after longer delay to prevent rapid repetition on the same page
                    setTimeout(() => {
                        hasAnnounced = false;
                    }, 10000);
                }
            }, true);

            const flashMessages = Array.from(document.querySelectorAll('.flash-stack .flash'))
                .map((item) => ({
                    text: item.textContent.trim(),
                    kind: Array.from(item.classList).find((cls) => cls !== 'flash') || '',
                }))
                .filter((item) => item.text);

            if (flashMessages.length) {
                const spokenMessage = flashMessages
                    .map((item) => {
                        if (item.kind.includes('success')) {
                            return `Success. ${item.text}`;
                        }
                        if (item.kind.includes('error')) {
                            return `There was a problem. ${item.text}`;
                        }
                        if (item.kind.includes('warning')) {
                            return `Warning. ${item.text}`;
                        }
                        return item.text;
                    })
                    .join(' ');

                setTimeout(() => {
                    this.speakFeedback(spokenMessage);
                }, 700);
            }

            if (this.context.isDashboard) {
                setTimeout(() => {
                    this.speakFeedback('Congratulations. You have successfully logged in to your account. You can now navigate using voice commands like logout, go to home, or read page.');
                }, 1200);
            }
        },

        speakFeedback(text) {
            const synth = window.speechSynthesis;
            if (synth && text) {
                // Cancel current speech
                synth.cancel();
                
                // Delay for browser compatibility
                setTimeout(() => {
                    const utterance = new SpeechSynthesisUtterance(text);
                    utterance.rate = 0.95;
                    utterance.pitch = 1;
                    // Only speak if not already speaking
                    if (!synth.speaking) {
                        synth.speak(utterance);
                    }
                }, 50);
            }
        },
    };

    voiceModule.init();

    window.VoiceModule = voiceModule;
});

document.addEventListener('keydown', (e) => {
    if (e.key === 'v' && e.ctrlKey && e.altKey) {
        e.preventDefault();
        const voiceToggle = document.querySelector('[data-voice-toggle]');
        if (voiceToggle) {
            voiceToggle.click();
        }
    }
});
