import logging
import random
import uuid
import wave
from difflib import SequenceMatcher
from pathlib import Path
from threading import Lock

import numpy as np
from django.conf import settings

logger = logging.getLogger(__name__)

SPEECHBRAIN_IMPORT_ERROR = None


_MODEL = None
_MODEL_LOCK = Lock()
_SPEECHBRAIN_CLASS = None


def normalize_phrase(phrase):
    return " ".join((phrase or "").strip().lower().split())


def phrase_matches_expected(candidate, expected):
    normalized_candidate = normalize_phrase(candidate)
    normalized_expected = normalize_phrase(expected)
    if not normalized_candidate or not normalized_expected:
        return False
    if normalized_candidate == normalized_expected:
        return True

    candidate_words = normalized_candidate.split()
    expected_words = normalized_expected.split()
    overlap = sum(1 for word in candidate_words if word in expected_words)
    required_overlap = max(len(expected_words) - 1, 1)
    similarity = SequenceMatcher(None, normalized_candidate, normalized_expected).ratio()

    return overlap >= required_overlap and similarity >= 0.72


def generate_voice_challenge():
    words = list(settings.VOICE_CHALLENGE_WORDS)
    count = min(4, len(words))
    if count < 3:
        return "secure cloud access"
    return " ".join(random.sample(words, count))


def _voice_storage_dir():
    path = Path(settings.MEDIA_ROOT) / "voice_biometrics"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _store_uploaded_audio(user, uploaded_file, label):
    target = _voice_storage_dir() / f"user-{user.pk}-{label}-{uuid.uuid4().hex}.wav"
    with target.open("wb") as stream:
        for chunk in uploaded_file.chunks():
            stream.write(chunk)
    return target


def _delete_file(path):
    try:
        Path(path).unlink(missing_ok=True)
    except Exception:
        logger.warning("Could not delete temporary voice sample: %s", path, exc_info=True)


def _load_audio(path):
    with wave.open(str(path), "rb") as wav_file:
        channels = wav_file.getnchannels()
        sample_width = wav_file.getsampwidth()
        sample_rate = wav_file.getframerate()
        frame_count = wav_file.getnframes()
        raw = wav_file.readframes(frame_count)

    if sample_width == 1:
        samples = (np.frombuffer(raw, dtype=np.uint8).astype(np.float32) - 128.0) / 128.0
    elif sample_width == 2:
        samples = np.frombuffer(raw, dtype="<i2").astype(np.float32) / 32768.0
    elif sample_width == 4:
        samples = np.frombuffer(raw, dtype="<i4").astype(np.float32) / 2147483648.0
    else:
        raise ValueError("Unsupported WAV sample width.")

    if channels > 1 and samples.size:
        samples = samples.reshape(-1, channels).mean(axis=1)
    return samples.astype(np.float32), sample_rate


def _resample_to_16khz(samples, sample_rate):
    if sample_rate == 16000 or not samples.size:
        return samples.astype(np.float32), 16000
    duration = samples.size / sample_rate
    target_count = max(1, int(duration * 16000))
    source_x = np.linspace(0.0, duration, num=samples.size, endpoint=False)
    target_x = np.linspace(0.0, duration, num=target_count, endpoint=False)
    return np.interp(target_x, source_x, samples).astype(np.float32), 16000


def _frame_audio(samples, frame_size=512, hop_size=256):
    if samples.size < frame_size:
        padded = np.zeros(frame_size, dtype=np.float32)
        padded[:samples.size] = samples
        return padded.reshape(1, frame_size)
    frame_count = 1 + (samples.size - frame_size) // hop_size
    shape = (frame_count, frame_size)
    strides = (samples.strides[0] * hop_size, samples.strides[0])
    return np.lib.stride_tricks.as_strided(samples, shape=shape, strides=strides).copy()


def _safe_stats(values):
    values = np.asarray(values, dtype=np.float32)
    if not values.size:
        return [0.0, 0.0, 0.0, 0.0]
    return [
        float(np.mean(values)),
        float(np.std(values)),
        float(np.percentile(values, 25)),
        float(np.percentile(values, 75)),
    ]


def _spectral_summary(samples, sample_rate):
    samples, sample_rate = _resample_to_16khz(samples, sample_rate)
    frames = _frame_audio(samples)
    window = np.hanning(frames.shape[1]).astype(np.float32)
    spectra = np.abs(np.fft.rfft(frames * window, axis=1)) + 1e-8
    power = spectra ** 2
    freqs = np.fft.rfftfreq(frames.shape[1], d=1.0 / sample_rate)
    power_sum = np.sum(power, axis=1) + 1e-8

    rms = np.sqrt(np.mean(frames ** 2, axis=1))
    zero_crossing = np.mean(np.diff(np.signbit(frames), axis=1), axis=1)
    centroid = np.sum(power * freqs, axis=1) / power_sum
    bandwidth = np.sqrt(np.sum(power * ((freqs - centroid[:, None]) ** 2), axis=1) / power_sum)
    cumulative = np.cumsum(power, axis=1)
    rolloff_index = np.argmax(cumulative >= (0.85 * power_sum[:, None]), axis=1)
    rolloff = freqs[rolloff_index]
    flatness = np.exp(np.mean(np.log(power), axis=1)) / (np.mean(power, axis=1) + 1e-8)

    band_edges = np.linspace(0, len(freqs) - 1, 13).astype(int)
    band_energies = []
    total_energy = np.sum(power, axis=1) + 1e-8
    for start, end in zip(band_edges[:-1], band_edges[1:]):
        band = np.sum(power[:, start:max(start + 1, end)], axis=1) / total_energy
        band_energies.extend(_safe_stats(band)[:2])

    summary = []
    for feature in (rms, zero_crossing, centroid, bandwidth, rolloff, flatness):
        summary.extend(_safe_stats(feature))
    summary.extend(band_energies)
    return np.array(summary, dtype=np.float32)


def extract_voice_embedding(path):
    samples, sample_rate = _load_audio(path)
    if not len(samples):
        return []
    embedding = _spectral_summary(samples, sample_rate)

    norm = float(np.linalg.norm(embedding))
    if norm > 0:
        embedding = embedding / norm
    return [round(float(value), 8) for value in embedding]


def cosine_similarity(left, right):
    left_vector = np.array(left, dtype=np.float32)
    right_vector = np.array(right, dtype=np.float32)
    if not left_vector.size or left_vector.shape != right_vector.shape:
        return 0.0
    denominator = float(np.linalg.norm(left_vector) * np.linalg.norm(right_vector))
    if denominator == 0:
        return 0.0
    return float(np.dot(left_vector, right_vector) / denominator)


def analyze_audio(path):
    samples, sample_rate = _load_audio(path)
    duration = len(samples) / sample_rate if sample_rate else 0
    rms = float(np.sqrt(np.mean(np.square(samples)))) if len(samples) else 0.0
    clipping_ratio = float(np.mean(np.abs(samples) >= 0.99)) if len(samples) else 1.0
    silence_threshold = max(0.003, rms * 0.35)
    silence_ratio = float(np.mean(np.abs(samples) < silence_threshold)) if len(samples) else 1.0

    summary = _spectral_summary(samples, sample_rate)
    normalized_centroid = float(summary[8] / 8000.0) if summary.size >= 9 else 0.0
    spectral_flatness = float(summary[20]) if summary.size >= 21 else 1.0

    risk = 0.0
    reasons = []

    if duration < settings.VOICE_MIN_DURATION_SECONDS:
        reasons.append("Recording was too short.")
        risk += 0.45
    if duration > settings.VOICE_MAX_DURATION_SECONDS:
        reasons.append("Recording was too long.")
        risk += 0.15
    if rms < settings.VOICE_MIN_RMS:
        reasons.append("Recording level was too low.")
        risk += 0.35
    if silence_ratio > settings.VOICE_MAX_SILENCE_RATIO:
        reasons.append("Too much silence was detected in the recording.")
        risk += 0.25
    if clipping_ratio > settings.VOICE_MAX_CLIPPING_RATIO:
        reasons.append("Audio clipping suggests the microphone was overloaded.")
        risk += 0.2
    if spectral_flatness < 0.0015:
        reasons.append("The recording looks unnaturally flat for a live voice sample.")
        risk += 0.2
    if normalized_centroid < 0.02 or normalized_centroid > 0.65:
        reasons.append("The recording spectrum was outside the expected speech range.")
        risk += 0.1

    risk = min(1.0, risk)
    accepted = risk <= settings.VOICE_MAX_SPOOF_RISK and duration >= settings.VOICE_MIN_DURATION_SECONDS and rms >= settings.VOICE_MIN_RMS
    return {
        "accepted": accepted,
        "risk": round(risk, 4),
        "duration": round(duration, 3),
        "rms": round(rms, 6),
        "silence_ratio": round(silence_ratio, 4),
        "clipping_ratio": round(clipping_ratio, 4),
        "spectral_flatness": round(spectral_flatness, 6),
        "normalized_centroid": round(normalized_centroid, 4),
        "reasons": reasons,
    }


class MockSpeakerVerifier:
    def verify(self, reference_path, candidate_path, *, reference_embedding=None):
        if not Path(reference_path).exists() or not Path(candidate_path).exists():
            return 0.0, False
        score = 0.95
        return score, True


class ClassicSpeakerVerifier:
    def verify(self, reference_path, candidate_path, *, reference_embedding=None):
        reference_vector = reference_embedding or extract_voice_embedding(reference_path)
        candidate_vector = extract_voice_embedding(candidate_path)
        if reference_embedding and len(reference_vector) != len(candidate_vector):
            reference_vector = extract_voice_embedding(reference_path)
        similarity = cosine_similarity(reference_vector, candidate_vector)
        return similarity, similarity >= settings.VOICE_CLASSIC_THRESHOLD


class SpeechBrainSpeakerVerifier:
    def __init__(self):
        self._predictor = None

    def _get_predictor(self):
        global _MODEL, _SPEECHBRAIN_CLASS, SPEECHBRAIN_IMPORT_ERROR
        if _MODEL is not None:
            return _MODEL
        with _MODEL_LOCK:
            if _MODEL is None:
                if _SPEECHBRAIN_CLASS is None:
                    try:
                        from speechbrain.inference.speaker import SpeakerRecognition
                        _SPEECHBRAIN_CLASS = SpeakerRecognition
                    except Exception as exc:  # pragma: no cover - optional backend
                        SPEECHBRAIN_IMPORT_ERROR = exc
                        raise RuntimeError(f"SpeechBrain import failed: {exc}") from exc
                _MODEL = _SPEECHBRAIN_CLASS.from_hparams(
                    source=settings.VOICE_MODEL_SOURCE,
                    savedir=settings.VOICE_MODEL_CACHE_DIR,
                )
        return _MODEL

    def verify(self, reference_path, candidate_path, *, reference_embedding=None):
        predictor = self._get_predictor()
        score, prediction = predictor.verify_files(
            str(reference_path),
            str(candidate_path),
            threshold=settings.VOICE_MODEL_THRESHOLD,
        )
        score_value = float(score.squeeze().item() if hasattr(score, "squeeze") else score)
        prediction_value = prediction.squeeze().item() if hasattr(prediction, "squeeze") else prediction
        return score_value, bool(prediction_value)


def _get_verifier():
    if settings.VOICE_BIOMETRIC_BACKEND == "mock":
        return MockSpeakerVerifier()
    if settings.VOICE_BIOMETRIC_BACKEND == "speechbrain":
        return SpeechBrainSpeakerVerifier()
    return ClassicSpeakerVerifier()


def enroll_user_voice(user, uploaded_file, spoken_phrase):
    audio_path = _store_uploaded_audio(user, uploaded_file, "reference")
    quality = analyze_audio(audio_path)
    if not quality["accepted"]:
        _delete_file(audio_path)
        return {
            "ok": False,
            "message": " ".join(quality["reasons"]) or "Voice recording quality was too low.",
            "quality": quality,
        }

    previous = user.voice_reference_audio_path
    relative_path = str(audio_path.relative_to(settings.MEDIA_ROOT))
    user.voice_enabled = True
    user.voice_phrase = normalize_phrase(spoken_phrase)
    user.voice_reference_audio_path = relative_path
    user.voice_profile_meta = {
        "enrollment_quality": quality,
        "backend": settings.VOICE_BIOMETRIC_BACKEND,
        "embedding": extract_voice_embedding(audio_path),
    }
    user.save(update_fields=[
        "voice_enabled",
        "voice_phrase",
        "voice_reference_audio_path",
        "voice_profile_meta",
    ])
    if previous:
        _delete_file(Path(settings.MEDIA_ROOT) / previous)
    return {"ok": True, "quality": quality}


def verify_user_voice(user, uploaded_file):
    if not user.voice_reference_audio_path:
        return {"ok": False, "message": "No voice profile is enrolled for this account."}

    candidate_path = _store_uploaded_audio(user, uploaded_file, "candidate")
    reference_path = Path(settings.MEDIA_ROOT) / user.voice_reference_audio_path
    quality = analyze_audio(candidate_path)
    if not quality["accepted"]:
        _delete_file(candidate_path)
        return {
            "ok": False,
            "message": " ".join(quality["reasons"]) or "Voice recording quality was too low.",
            "quality": quality,
        }

    try:
        score, accepted = _get_verifier().verify(
            reference_path,
            candidate_path,
            reference_embedding=(user.voice_profile_meta or {}).get("embedding"),
        )
    except Exception as exc:
        logger.exception("Voice verification backend failed.")
        _delete_file(candidate_path)
        return {
            "ok": False,
            "message": f"Voice verification backend failed: {exc}",
            "quality": quality,
        }

    _delete_file(candidate_path)
    return {
        "ok": accepted,
        "score": round(score, 4),
        "quality": quality,
        "message": "Voice verification passed." if accepted else "The speaker verification score was below the acceptance threshold.",
    }
