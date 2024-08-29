import argparse
import csv
from collections import defaultdict


class LogAggregator:
    """Aggregates network flow log data to generate statistics based on destination ports and protocols.
    
    This class is designed to work with CSV files that map network protocols and ports to specific tags,
    and flow log files that list network traffic events.
    
    Attributes:
        lookup_table (Dict[Tuple[int, str], str]): A dictionary mapping (port, protocol) to tags.
        protocol_lookup (Dict[str, str]): A dictionary mapping protocol numbers to protocol names.
    """

    def __init__(self, lookup_file, protocol_file):
        """Initializes the LogAggregator with lookup tables for ports, protocols, and their corresponding tags.

        Args:
            lookup_file (str): Path to the CSV file containing port, protocol, and tag mappings.
            protocol_file (str): Path to the CSV file containing protocol number to protocol name mappings.
        """
        self.lookup_table = self._load_lookup_table(lookup_file)
        self.protocol_lookup = self._load_protocol_numbers(protocol_file)

    def _load_lookup_table(self, lookup_file):
        """Loads a lookup table from a specified CSV file.

        Args:
            lookup_file (str): Path to the CSV file to load.

        Returns:
            Dict[Tuple[int, str], str]: A dictionary with (port, protocol) tuples as keys and tags as values.
        """
        lookup_table = {}
        with open(lookup_file, mode='r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                key = (int(row['dstport']), row['protocol'].lower())
                lookup_table[key] = row['tag'].lower()
        return lookup_table

    def _load_protocol_numbers(self, protocol_file):
        """Loads protocol numbers and their corresponding names from a CSV file.

        Args:
            protocol_file (str): Path to the CSV file to load.

        Returns:
            Dict[str, str]: A dictionary mapping protocol numbers to protocol names.
        """
        protocol_numbers = {}
        with open(protocol_file, mode='r') as file:
            reader = csv.reader(file)
            for row in reader:
                protocol_numbers[row[0]] = row[1].lower()
        return protocol_numbers

    def process_flow_logs(self, flow_log_file):
        """Processes flow logs from a file to generate tag and port-protocol statistics.

        Args:
            flow_log_file (str): Path to the flow log file.

        Returns:
            Tuple[Dict[str, int], Dict[Tuple[int, str], int]]: Two dictionaries containing tag counts and
            port-protocol combination counts respectively.
        """
        tag_count = defaultdict(int)
        port_protocol_count = defaultdict(int)

        with open(flow_log_file, mode='r') as file:
            for line in file:
                parts = line.split()
                dstport = int(parts[6])
                protocol = self.protocol_lookup.get(parts[7], 'other').lower()
                key = (dstport, protocol)

                port_protocol_count[key] += 1

                tag = self.lookup_table.get(key, 'untagged')
                tag_count[tag] += 1

        return tag_count, port_protocol_count

    def save_results(self, tag_count, port_protocol_count, output_file):
        """Saves the processed tag and port-protocol statistics to an output file.

        Args:
            tag_count (Dict[str, int]): A dictionary of tag counts.
            port_protocol_count (Dict[Tuple[int, str], int]): A dictionary of port-protocol combination counts.
            output_file (str): Path to the file where results should be saved.
        """
        with open(output_file, mode='w') as file:
            file.write("Tag Counts:\n")
            file.write("Tag,Count\n")
            for tag, count in tag_count.items():
                file.write(f"{tag},{count}\n")

            file.write("\nPort/Protocol Combination Counts:\n")
            file.write("Port,Protocol,Count\n")
            for (port, protocol), count in port_protocol_count.items():
                file.write(f"{port},{protocol},{count}\n")

def get_args():
    parser = argparse.ArgumentParser(description="Process network flow logs to generate statistical data.")
    parser.add_argument('--lookup_file', type=str, default='lookup_table.csv', help='Path to the CSV file containing port, protocol, and tag mappings.')
    parser.add_argument('--protocol_file', type=str, default='protocol-numbers.csv', help='Path to the CSV file containing protocol number to protocol name mappings.')
    parser.add_argument('--flow_log_file', type=str, default='flow-log.log', help='Path to the flow log file.')
    parser.add_argument('--output_file', type=str, default='output_results.txt', help='Path to the file where results should be saved.')
    args = parser.parse_args()
    return vars(args)

def main(**kwargs):
    processor = LogAggregator(kwargs['lookup_file'], kwargs['protocol_file'])
    tag_count, port_protocol_count = processor.process_flow_logs(kwargs['flow_log_file'])
    processor.save_results(tag_count, port_protocol_count, kwargs['output_file'])

if __name__ == '__main__':
    args = get_args()
    main(**args)