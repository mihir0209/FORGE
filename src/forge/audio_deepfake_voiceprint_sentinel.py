from dataclasses import dataclass
from typing import List

@dataclass
class AudioLivenessResult:
    is_deepfake_voice: bool
    spectral_centroid_hz: float
    jitter_shimmer_ratio: float
    threat_tier: str

class AudioDeepfakeVoiceprintSentinel:
    def evaluate_voice_audio(
        self,
        spectral_centroid_hz: float,
        pitch_variance_semitones: float,
        synthetic_phase_discontinuity_score: float
    ) -> AudioLivenessResult:
        # Synthetic speech vocoders (e.g. ElevenLabs, VALL-E) produce unnaturally flat pitch variance (<1.2)
        # or elevated phase discontinuities (>0.70)
        is_synthetic_pitch = pitch_variance_semitones < 1.2
        is_phase_artifact = synthetic_phase_discontinuity_score >= 0.70

        is_deepfake = is_synthetic_pitch or is_phase_artifact
        tier = "CRITICAL_AI_VOICE_CLONE" if (is_synthetic_pitch and is_phase_artifact) else (
            "SUSPECTED_VOICE_SYNTHESIS" if is_deepfake else "AUTHENTIC_HUMAN_VOICE"
        )

        return AudioLivenessResult(
            is_deepfake_voice=is_deepfake,
            spectral_centroid_hz=round(spectral_centroid_hz, 1),
            jitter_shimmer_ratio=round(pitch_variance_semitones, 2),
            threat_tier=tier
        )
