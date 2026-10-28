from dataclasses import dataclass
from typing import List

@dataclass
class LivenessResult:
    is_live: bool
    confidence_score: float
    flag: str

class DeepfakeBiometricsLivenessSentinel:
    def evaluate_video_stream(
        self,
        frame_count: int,
        blink_timestamps_sec: List[float],
        frequency_artifact_score: float
    ) -> LivenessResult:
        if frame_count < 30:
            return LivenessResult(False, 0.0, "INSUFFICIENT_FRAMES")

        duration_sec = frame_count / 30.0
        blink_rate_per_min = (len(blink_timestamps_sec) / max(1.0, duration_sec)) * 60.0

        # Normal human blink rate: 10 to 30 blinks per minute
        # Deepfakes often have 0 blinks or erratic unnatural blinking (>60)
        unnatural_blink = blink_rate_per_min < 5.0 or blink_rate_per_min > 50.0
        synthetic_texture = frequency_artifact_score >= 0.75

        is_deepfake = unnatural_blink or synthetic_texture
        confidence = 0.95 if (unnatural_blink and synthetic_texture) else 0.85

        return LivenessResult(
            is_live=not is_deepfake,
            confidence_score=confidence if is_deepfake else 0.90,
            flag="DEEPFAKE_ARTIFACT_DETECTED" if is_deepfake else "AUTHENTIC_BIOMETRICS"
        )
