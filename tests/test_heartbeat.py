from dataclasses import replace
from attestation.heartbeat import verify_heartbeat
from attestation.schema import generate_demo_key, load_public_key, public_key_bytes, sign_heartbeat
from cap.models import Heartbeat, VerificationStatus

def test_heartbeat_valid_previous_and_missing():
    key = generate_demo_key(); keys = {"k": load_public_key(public_key_bytes(key))}
    hb = sign_heartbeat(Heartbeat("h", 10, "2026-01-01T00:00:00Z", 9, "clock", "k"), key)
    assert verify_heartbeat(hb, 10, keys).status is VerificationStatus.VALID
    assert verify_heartbeat(replace(hb, previous_sequence=8), 10, keys).reasons == ("HEARTBEAT_PREVIOUS_SEQUENCE_MISMATCH",)
    assert verify_heartbeat(None, 10, keys).status is VerificationStatus.UNKNOWN
