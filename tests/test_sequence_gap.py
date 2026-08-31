from attestation.sequence import verify_sequence
from cap.models import VerificationStatus

def test_sequence_contiguous_gap_and_out_of_order():
    assert verify_sequence(1043, 1043).status is VerificationStatus.VALID
    assert verify_sequence(1043, 1044).reasons == ("ATTESTATION_SEQUENCE_GAP",)
    assert verify_sequence(1043, 1042).reasons == ("ATTESTATION_SEQUENCE_OUT_OF_ORDER",)
