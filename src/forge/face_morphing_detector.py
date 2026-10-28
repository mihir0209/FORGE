from dataclasses import dataclass
from typing import List

@dataclass
class FaceMorphingAssessment:
    is_morphed_image: bool
    blending_boundary_score: float
    landmark_symmetry_residual: float
    decision: str

class FaceMorphingDetector:
    def evaluate_biometric_facial_mesh(
        self,
        edge_gradient_discontinuity: float,
        landmark_bilateral_residual: float,
        jpeg_ghost_score: float
    ) -> FaceMorphingAssessment:
        # Morphing creates high frequency boundary artifacts and asymmetrical blending ghosts
        is_morph = (edge_gradient_discontinuity >= 0.65 and landmark_bilateral_residual >= 0.45) or jpeg_ghost_score >= 0.80
        decision = "FLAG_FOR_MANUAL_KYC_AUDIT" if is_morph else "PASS_BIOMETRIC_CHECK"

        return FaceMorphingAssessment(
            is_morphed_image=is_morph,
            blending_boundary_score=round(edge_gradient_discontinuity, 2),
            landmark_symmetry_residual=round(landmark_bilateral_residual, 2),
            decision=decision
        )
