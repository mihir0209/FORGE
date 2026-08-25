"""Versioned payment-rail profiles used by dynamic fraud families."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PaymentRailProfile:
    slug: str
    version: str
    lifecycle: tuple[str, ...]
    finality: str
    payee_verification: str | None
    supports_hold: bool
    supports_recall: bool
    max_amount_minor: int | None


RAILS: dict[str, PaymentRailProfile] = {
    "upi": PaymentRailProfile("upi", "2026.1", ("intent", "payee_verification", "device_binding", "upi_pin", "rail_acceptance", "settlement"), "instant_push", None, False, True, None),
    "upi_lite": PaymentRailProfile("upi_lite", "2026.1", ("intent", "device_balance_check", "local_debit", "merchant_credit"), "on_device_low_value", None, False, True, 100_000),
    "upi_circle": PaymentRailProfile("upi_circle", "2026.1", ("delegation_check", "limit_check", "authorization", "rail_acceptance", "settlement"), "delegated_instant_push", None, False, True, 500_000),
    "faster_payments": PaymentRailProfile("faster_payments", "2026.1", ("intent", "confirmation_of_payee", "authorization", "rail_acceptance", "settlement", "app_reimbursement"), "instant_push", "confirmation_of_payee", False, True, None),
    "sepa_instant": PaymentRailProfile("sepa_instant", "2025.1", ("intent", "verification_of_payee", "authorization", "rail_acceptance", "settlement"), "ten_second_push", "verification_of_payee", False, True, None),
    "fednow": PaymentRailProfile("fednow", "2026.1", ("intent", "payee_name_verification", "authorization", "rail_acceptance", "settlement"), "instant_push", "payee_name_verification", False, True, None),
    "rtp": PaymentRailProfile("rtp", "2026.1", ("intent", "authorization", "rail_acceptance", "settlement", "return_request"), "irrevocable_push", None, False, True, 1_000_000_000),
    "card": PaymentRailProfile("card", "emv-2026", ("authentication", "authorization_hold", "capture", "clearing", "settlement", "dispute"), "reversible_lifecycle", None, True, True, None),
    "open_banking": PaymentRailProfile("open_banking", "2026.1", ("consent", "sca", "payment_order", "rail_acceptance", "settlement"), "a2a_push", "verification_of_payee", False, True, None),
    "stablecoin_offramp": PaymentRailProfile("stablecoin_offramp", "2026.1", ("wallet_transfer", "confirmations", "screening", "conversion", "fiat_withdrawal"), "chain_dependent", None, True, True, None),
}


def rail_profile(slug: str) -> PaymentRailProfile:
    try:
        return RAILS[slug]
    except KeyError as exc:
        raise ValueError(f"unsupported payment rail: {slug}") from exc
