from dataclasses import dataclass


@dataclass
class RiskResult:
    score: int
    status: str
    recommendation: str
    categories: list[str]


def score_to_status(score: int) -> str:
    if score <= 30:
        return "SAFE"
    if score <= 70:
        return "SUSPICIOUS"
    return "MALICIOUS"


def recommendation_for(score: int, categories: list[str]) -> str:
    if score >= 71:
        return "Dərhal bloklayın"
    if score >= 31 or categories:
        return "Nəzarətdə saxlayın"
    return "Təhlükə yoxdur"


def compute_risk(base_score: int, category_weights: dict[str, int]) -> RiskResult:
    extra = sum(category_weights.values())
    score = max(0, min(100, base_score + extra))
    categories = [k for k, v in category_weights.items() if v > 0]
    status = score_to_status(score)
    return RiskResult(
        score=score,
        status=status,
        recommendation=recommendation_for(score, categories),
        categories=categories,
    )
