from dataclasses import dataclass

@dataclass
class SessionTicketAudit:
    is_compromised_risk: bool
    rotation_overdue: bool
    ticket_lifetime_hours: float
    recommendation: str

class TlsSessionTicketSentinel:
    def audit_session_ticket_rotation(
        self,
        key_age_hours: float,
        max_allowed_lifetime_hours: float = 24.0,
        forward_secrecy_enabled: bool = True
    ) -> SessionTicketAudit:
        is_overdue = key_age_hours > max_allowed_lifetime_hours
        risk = is_overdue or not forward_secrecy_enabled

        rec = "ROTATE_SESSION_TICKET_ENCRYPTION_KEY_IMMEDIATELY" if risk else "COMPLIANT"

        return SessionTicketAudit(
            is_compromised_risk=risk,
            rotation_overdue=is_overdue,
            ticket_lifetime_hours=round(key_age_hours, 1),
            recommendation=rec
        )
