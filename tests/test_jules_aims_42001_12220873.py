import pytest
from iso9000_agentops.aims_42001 import compute_fmea_rpn

def test_compute_fmea_rpn_boundaries():
    # Min boundary
    result_min = compute_fmea_rpn(1, 1, 1)
    assert result_min["severity"] == 1
    assert result_min["occurrence"] == 1
    assert result_min["detection"] == 1
    assert result_min["rpn"] == 1

    # Max boundary
    result_max = compute_fmea_rpn(10, 10, 10)
    assert result_max["severity"] == 10
    assert result_max["occurrence"] == 10
    assert result_max["detection"] == 10
    assert result_max["rpn"] == 1000

    # Severity boundaries
    result_s1 = compute_fmea_rpn(1, 5, 5)
    assert result_s1["severity"] == 1
    result_s10 = compute_fmea_rpn(10, 5, 5)
    assert result_s10["severity"] == 10

    # Occurrence boundaries
    result_o1 = compute_fmea_rpn(5, 1, 5)
    assert result_o1["occurrence"] == 1
    result_o10 = compute_fmea_rpn(5, 10, 5)
    assert result_o10["occurrence"] == 10

    # Detection boundaries
    result_d1 = compute_fmea_rpn(5, 5, 1)
    assert result_d1["detection"] == 1
    result_d10 = compute_fmea_rpn(5, 5, 10)
    assert result_d10["detection"] == 10

def test_compute_fmea_rpn_out_of_bounds():
    with pytest.raises(ValueError, match="severity must be between 1 and 10 inclusive"):
        compute_fmea_rpn(0, 5, 5)
    with pytest.raises(ValueError, match="severity must be between 1 and 10 inclusive"):
        compute_fmea_rpn(11, 5, 5)

    with pytest.raises(ValueError, match="occurrence must be between 1 and 10 inclusive"):
        compute_fmea_rpn(5, 0, 5)
    with pytest.raises(ValueError, match="occurrence must be between 1 and 10 inclusive"):
        compute_fmea_rpn(5, 11, 5)

    with pytest.raises(ValueError, match="detection must be between 1 and 10 inclusive"):
        compute_fmea_rpn(5, 5, 0)
    with pytest.raises(ValueError, match="detection must be between 1 and 10 inclusive"):
        compute_fmea_rpn(5, 5, 11)

def test_compute_fmea_rpn_invalid_types():
    with pytest.raises(ValueError, match="severity must be an integer"):
        compute_fmea_rpn(True, 5, 5)  # type: ignore
    with pytest.raises(ValueError, match="severity must be an integer"):
        compute_fmea_rpn(1.5, 5, 5)  # type: ignore
    with pytest.raises(ValueError, match="severity must be an integer"):
        compute_fmea_rpn(None, 5, 5)  # type: ignore

    with pytest.raises(ValueError, match="occurrence must be an integer"):
        compute_fmea_rpn(5, False, 5)  # type: ignore
    with pytest.raises(ValueError, match="detection must be an integer"):
        compute_fmea_rpn(5, 5, "10")  # type: ignore
