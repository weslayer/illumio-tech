from pathlib import Path
from main import parse_flow_log, get_protocol_name, load_tag_mappings, process_flow_logs, Results
import os
import pytest

TEST_DIR = Path('test_data')
os.makedirs(TEST_DIR, exist_ok=True)

@pytest.fixture
def test_dir():
    """Create and return test directory with sample files."""
    os.makedirs(TEST_DIR, exist_ok=True)
    
    with open(TEST_DIR / "tag_mappings.csv", 'w') as f:
        f.write("""dstport,protocol,tag
25,tcp,sv_P1
68,udp,sv_P2
23,tcp,sv_P1
31,udp,SV_P3
443,tcp,sv_P2
22,tcp,sv_P4
3389,tcp,sv_P5
0,icmp,sv_P5
110,tcp,email
993,tcp,email
143,tcp,email""")
    
    with open(TEST_DIR / "flow_logs.txt", 'w') as f:
        f.write("""2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2 49153 443 6 25 20000 1620140761 1620140821 ACCEPT OK
2 123456789012 eni-4d3c2b1a 192.168.1.100 203.0.113.101 49154 23 6 15 12000 1620140761 1620140821 REJECT OK
2 123456789012 eni-5e6f7g8h 192.168.1.101 198.51.100.3 49155 25 6 10 8000 1620140761 1620140821 ACCEPT OK
2 123456789012 eni-9h8g7f6e 172.16.0.100 203.0.113.102 49156 110 6 12 9000 1620140761 1620140821 ACCEPT OK""")
    
    yield TEST_DIR
    
    for file in TEST_DIR.glob("*"):
        file.unlink()
    TEST_DIR.rmdir()

@pytest.mark.parametrize("line,expected", [
    ("2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2 443 49153 6 25 20000 1620140761 1620140821 ACCEPT OK", {
        "version": 2,
        "acc_id": "123456789012",
        "interface_id": "eni-0a1b2c3d",
        "src_addr": "10.0.1.201",
        "dst_addr": "198.51.100.2",
        "src_port": 443,
        "dst_port": 49153,
        "protocol": 6,
        "packets": 25,
        "bytes": 20000,
        "start_time": 1620140761,
        "end_time": 1620140821,
        "action": "ACCEPT",
        "log_status": "OK"
    })
])
def test_parse_flow_log(line, expected):
    """Test parsing a flow log line into a FlowLog object."""
    log = parse_flow_log(line)
    for field, value in expected.items():
        assert getattr(log, field) == value

@pytest.mark.parametrize("protocol_num,expected", [
    (6, "tcp"),
    (17, "udp"),
    (1, "icmp"),
    (999, "unknown")
])
def test_get_protocol_name(protocol_num, expected):
    """Test protocol number to name conversion."""
    assert get_protocol_name(protocol_num) == expected

def test_load_tag_mappings(test_dir):
    """Test loading tag mappings from CSV file."""
    tag_mappings = load_tag_mappings(test_dir)
    
    expected_mappings = {
        (25, "tcp"): "sv_P1",
        (68, "udp"): "sv_P2",
        (23, "tcp"): "sv_P1",
        (31, "udp"): "SV_P3",
        (443, "tcp"): "sv_P2",
        (22, "tcp"): "sv_P4",
        (3389, "tcp"): "sv_P5",
        (0, "icmp"): "sv_P5",
        (110, "tcp"): "email",
        (993, "tcp"): "email",
        (143, "tcp"): "email"
    }
    
    for key, value in expected_mappings.items():
        assert tag_mappings[key] == value

def test_process_flow_logs(test_dir):
    """Test processing flow logs and counting tags."""
    tag_mappings = load_tag_mappings(test_dir)
    results = process_flow_logs(test_dir, "flow_logs.txt", tag_mappings)
    
    expected_tag_counts = {
        "sv_P1": 2,  # Port 25 and 23
        "sv_P2": 1,  # Port 443
        "email": 1,  # Port 110
    }
    assert results.tag_counts == expected_tag_counts
    
    expected_port_counts = {
        (23, "tcp"): 1,
        (25, "tcp"): 1,
        (443, "tcp"): 1,
        (110, "tcp"): 1
    }
    assert results.port_protocol_counts == expected_port_counts

def test_process_flow_logs_untagged(test_dir):
    """Test handling of untagged flows."""
    results = process_flow_logs(test_dir, "flow_logs.txt", {})
    assert results.tag_counts == {"Untagged": 4}
    assert results.port_protocol_counts == {
        (443, "tcp"): 1,
        (23, "tcp"): 1,
        (25, "tcp"): 1,
        (110, "tcp"): 1
    }

def test_process_flow_logs_mixed_tagging(test_dir):
    """Test processing with both tagged and untagged flows."""
    partial_tag_mappings = {
        (443, "tcp"): "sv_P2",
        (25, "tcp"): "sv_P1"
    }
    
    results = process_flow_logs(test_dir, "flow_logs.txt", partial_tag_mappings)
    
    expected_tag_counts = {
        "sv_P1": 1,  # Port 25
        "sv_P2": 1,  # Port 443
        "Untagged": 2  # Ports 23 and 110 don't have mappings
    }
    assert results.tag_counts == expected_tag_counts
    
    expected_port_counts = {
        (23, "tcp"): 1,
        (25, "tcp"): 1,
        (443, "tcp"): 1,
        (110, "tcp"): 1
    }
    assert results.port_protocol_counts == expected_port_counts

def test_process_flow_logs_unknown_protocol(test_dir):
    """Test handling of flows with unknown protocols."""
    with open(TEST_DIR / "unknown_protocol.txt", 'w') as f:
        f.write("""2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2 49153 443 99 25 20000 1620140761 1620140821 ACCEPT OK""")
    
    results = process_flow_logs(test_dir, "unknown_protocol.txt", {
        (443, "unknown"): "tagged_unknown"
    })
    
    expected_tag_counts = {
        "tagged_unknown": 1
    }
    assert results.tag_counts == expected_tag_counts
    assert results.port_protocol_counts == {(443, "unknown"): 1}

def test_process_empty_flow_logs(test_dir):
    """Test processing an empty flow logs file."""
    with open(TEST_DIR / "empty.txt", 'w') as f:
        f.write("")
    
    tag_mappings = load_tag_mappings(test_dir)
    results = process_flow_logs(test_dir, "empty.txt", tag_mappings)
    
    assert results.tag_counts == {}
    assert results.port_protocol_counts == {}
