"""Bulk cleanup must not delete people or records.

Every case here mirrors the shape of a real-world message type, not imagination.
The false positives in particular are the kind only found by eyeballing a dry
run, which is why they are pinned.
"""
from __future__ import annotations

import pytest

from icloud_mcp.config import CleanupRule
from icloud_mcp.models import Message
from icloud_mcp.protect import (
    deletion_block, is_otp, is_protected_sender, protect_reason,
)
from icloud_mcp.rules import plan_cleanup


def msg(uid=1, frm="noreply@example.com", subject=""):
    return Message(uid=uid, from_addr=frm, subject=subject)


# ---------------------------------------------------------------- senders
# The real list is personal and lives in config.toml (gitignored), so these use
# a stand-in set exactly the way parse_config feeds one in.
CONFIGURED = {"colleague@example.com", "friend@example.com"}


@pytest.mark.parametrize("addr", [
    "colleague@example.com",
    "Colleague@Example.COM",     # case-insensitive: config may be typed either way
    "  friend@example.com  ",     # and padded
])
def test_configured_people_are_protected(addr):
    assert is_protected_sender(addr, CONFIGURED)


def test_nothing_is_protected_by_default():
    """Shipping a hardcoded list would leak personal addresses to every install."""
    assert not is_protected_sender("colleague@example.com")
    assert not is_protected_sender("no.reply.alerts@bank.example.com", CONFIGURED)
    assert not is_protected_sender("", CONFIGURED)


# ---------------------------------------------------------------- records
@pytest.mark.parametrize("subj,cat", [
    ("Your Example Airlines booking confirmation - ABC123", "travel"),
    ("Your party has been assigned seats on your flight to Example City", "travel"),
    ("Quick reminders about your upcoming trip", "travel"),
    ("Travel itinerary from Example Airlines", "travel"),
    ("3-Day Fare Hold Reservation", "travel"),
    # matches the travel family first, which is the more specific label. Either
    # category protects it; what matters is that it is never None.
    ("Your flight cancellation is confirmed", "travel"),
    ("ATTENTION: Important Safety Notice about your Past Order", "safety"),
    ("Your purchase is now available to download. ($12.34)", "financial"),
    ("Important Notice: Your July 2026 Statement", "financial"),
    ("Your receipt from Apple.", "financial"),
    ("Example Utility - Online Receipt", "financial"),
    ("Your return has been processed.", "order"),
    ("Alex, your coverage has been cancelled.", "cancellation"),
])
def test_real_records_are_protected(subj, cat):
    assert protect_reason(subj) == cat


@pytest.mark.parametrize("subj", [
    # Airlines send bare operational notices with no prose. These matched none of
    # the wordy travel patterns, which is why the shape-based pattern exists.
    "XY83 JFK-LAX 03JAN",
    "XY 1234 SFO-ORD 12MAR",
    "Now boarding your flight to Example City at Gate A1",
])
def test_bare_operational_flight_notices(subj):
    assert protect_reason(subj) == "travel"


@pytest.mark.parametrize("subj", [
    "Don't Miss the Tax Credit Deadline",              # marketing, not a tax doc
    "Save With the Tax Credit",
    "Here's Your Boarding Pass - Up to 50% Off",        # retailer sale pun
    "Final Hours! Our Summer Favorites Sale Ends Tonight",
    "Big Summer Deals End Today!",
])
def test_marketing_lookalikes_are_not_protected(subj):
    assert protect_reason(subj) is None


# ---------------------------------------------------------------- OTP
@pytest.mark.parametrize("subj", [
    "000000 is your ExampleDrive security code",
    "Your login code is 000 000",
    "Here's your ExampleApp verification code",
    "Your Card Verification Code",
    "Your temporary ExampleChat login code",
    "ABCDEF is your verification code for ExampleTix",
    "Login verification code (example.com)",
])
def test_real_codes_are_otp(subj):
    assert is_otp(subj)


@pytest.mark.parametrize("subj", [
    "Two-factor authentication enabled for your Apple ID",   # security EVENT, keep
    "2FA bound to your account",
    "ExampleHome Two-Factor Authentication enabled",
    "Here is Your 30% Discount Code for Your Order",         # marketing code
    "Your Apple ID was used to sign in to iCloud on an iPhone.",
    "Bank security alert: You signed in with a new device",
])
def test_events_and_promos_are_not_otp(subj):
    assert not is_otp(subj)


def test_expired_code_beats_a_protected_word():
    """'confirmation code' must not be rescued by the 'cancellation/confirm' family."""
    assert deletion_block("x@y.com", "Your confirmation code is 123456") is None


# ---------------------------------------------------------------- wiring
def test_plan_cleanup_blocks_delete_of_a_record():
    rules = [CleanupRule(match="notifications@airline.example.com", action="delete")]
    m = msg(frm="notifications@airline.example.com",
            subject="Your Example Airlines booking confirmation - ABC123")
    plan = plan_cleanup([m], rules, allow_delete=True)
    assert plan[0]["action"] == "skip"
    assert "protected subject (travel)" in plan[0]["note"]


def test_plan_cleanup_blocks_delete_of_a_person():
    rules = [CleanupRule(match="colleague@example.com", action="delete")]
    plan = plan_cleanup([msg(frm="colleague@example.com", subject="RE: Portal")],
                        rules, allow_delete=True, protected_senders=CONFIGURED)
    assert plan[0]["action"] == "skip"
    assert "protected sender" in plan[0]["note"]


def test_plan_cleanup_deletes_that_person_when_config_is_empty():
    """Proves the block comes from config, not from a hidden hardcoded list."""
    rules = [CleanupRule(match="colleague@example.com", action="delete")]
    plan = plan_cleanup([msg(frm="colleague@example.com", subject="RE: Portal")],
                        rules, allow_delete=True)
    assert plan[0]["action"] == "delete"


def test_plan_cleanup_blocks_move_to_trash_too():
    """Moving to Deleted Messages is a delete wearing a different hat."""
    rules = [CleanupRule(match="notifications@airline.example.com", action="move",
                         folder="Deleted Messages")]
    m = msg(frm="notifications@airline.example.com", subject="Travel itinerary from Example Airlines")
    assert plan_cleanup([m], rules, allow_delete=True)[0]["action"] == "skip"


def test_plan_cleanup_allows_archive_of_a_record():
    """Protection is about not LOSING mail, not about never touching it."""
    rules = [CleanupRule(match="notifications@airline.example.com", action="archive")]
    m = msg(frm="notifications@airline.example.com", subject="Travel itinerary from Example Airlines")
    assert plan_cleanup([m], rules, allow_delete=True)[0]["action"] == "archive"


def test_plan_cleanup_still_deletes_ordinary_marketing():
    rules = [CleanupRule(match="newsletter@shop.example.com", action="delete")]
    m = msg(frm="newsletter@shop.example.com", subject="Don't Miss the Tax Credit Deadline")
    assert plan_cleanup([m], rules, allow_delete=True)[0]["action"] == "delete"


def test_allow_delete_false_still_wins_for_unprotected():
    rules = [CleanupRule(match="newsletter@shop.example.com", action="delete")]
    plan = plan_cleanup([msg(frm="newsletter@shop.example.com", subject="Meet the New Collection")],
                        rules, allow_delete=False)
    assert plan[0]["action"] == "skip"
    assert "allow_delete" in plan[0]["note"]
