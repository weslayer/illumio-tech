from dataclasses import dataclass
from typing import Dict, Tuple
import csv
from pathlib import Path
import os
import socket

@dataclass
class FlowLog:
    version: int
    acc_id: str
    interface_id: str
    src_addr: str
    dst_addr: str
    src_port: int
    dst_port: int
    protocol: int
    packets: int
    bytes: int
    start_time: int
    end_time: int
    action: str
    log_status: str

@dataclass
class TagMapping:
    dst_port: int
    protocol: str
    tag: str

@dataclass
class Results:
    tag_counts: Dict[str, int]
    port_protocol_counts: Dict[Tuple[int, str], int]

def load_tag_mappings(mapping_dir: Path) -> Dict[Tuple[int, str], str]:
    tag_mappings: Dict[Tuple[int, str], str] = {}
    with open(mapping_dir / 'tag_mappings.csv', 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            dst_port = int(row['dstport'])
            protocol = row['protocol'].lower()
            tag = row['tag']
            tag_mappings[(dst_port, protocol)] = tag
    return tag_mappings

def parse_flow_log(line: str) -> FlowLog:
    fields = line.strip().split()
    return FlowLog(
        version=int(fields[0]),
        acc_id=fields[1],
        interface_id=fields[2],
        src_addr=fields[3],
        dst_addr=fields[4],
        src_port=int(fields[5]),
        dst_port=int(fields[6]), # important
        protocol=int(fields[7]), # important
        packets=int(fields[8]),
        bytes=int(fields[9]),
        start_time=int(fields[10]),
        end_time=int(fields[11]),
        action=fields[12],
        log_status=fields[13]
    )

def get_protocol_name(protocol_num: int) -> str:
    """https://pymotw.com/2/socket/addressing.html"""
    protocol_table = dict((getattr(socket, n), n)
                 for n in dir(socket)
                 if n.startswith("IPPROTO_")
                 )
    protocol_name = protocol_table.get(protocol_num, str(protocol_num))
    return protocol_name[8:].lower() # strip IPPROTO_ from name

def process_flow_logs(input_dir: Path, log_file: str, tag_mappings: Dict[Tuple[int, str], str]) -> Results:
    """Main function that processes the logs and increments the tags and port/protocol combinations."""
    tag_counts: Dict[str, int] = {}
    port_protocol_counts: Dict[Tuple[int, str], int] = {}
    
    with open(input_dir / log_file, 'r') as f:
        for line in f:
            if not line.strip():
                continue
                
            log = parse_flow_log(line)
            protocol_str = get_protocol_name(log.protocol)
            
            # increment port/protocol combinations
            port_proto_key = (log.dst_port, protocol_str)
            port_protocol_counts[port_proto_key] = port_protocol_counts.get(port_proto_key, 0) + 1
            
            # increment count
            tag = tag_mappings.get((log.dst_port, protocol_str), 'Untagged')
            tag_counts[tag] = tag_counts.get(tag, 0) + 1
    
    return Results(tag_counts=tag_counts, port_protocol_counts=port_protocol_counts)

def write_results(output_dir: Path, results: Results) -> None:
    """Write results to output files."""
    # Write tag counts
    with open(output_dir / 'tag_counts.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Tag', 'Count'])
        for tag, count in sorted(results.tag_counts.items()):
            writer.writerow([tag, count])

    # Write port/protocol counts
    with open(output_dir / 'port_protocol_counts.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Port', 'Protocol', 'Count'])
        for (port, protocol), count in sorted(results.port_protocol_counts.items()):
            writer.writerow([port, protocol, count])

def main():
    os.makedirs('output', exist_ok=True)

    input_dir = Path('input')
    output_dir = Path('output')
    mappings = Path('mappings')
    
    # Process files
    tag_mappings = load_tag_mappings(mappings / 'tag_mappings.csv')
    results = process_flow_logs(input_dir, 'flow_logs.txt', tag_mappings)
    write_results(output_dir, results)

if __name__ == '__main__':
    main()
