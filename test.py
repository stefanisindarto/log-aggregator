import unittest
from main import LogAggregator
import os
import csv

class TestLogAggregator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Setup for the test
        cls.lookup_file = 'test_lookup.csv'
        cls.protocol_file = 'test_protocol.csv'
        cls.flow_log_file = 'test_flow.log'
        cls.output_file = 'test_output.txt'

        # Create test lookup file
        with open(cls.lookup_file, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['dstport', 'protocol', 'tag'])
            writer.writerow([80, 'tcp', 'Web Traffic'])
            writer.writerow([443, 'tcp', 'Secure Web Traffic'])

        # Create test protocol file
        with open(cls.protocol_file, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['6', 'TCP'])
            writer.writerow(['17', 'UDP'])

        # Create test flow log file
        with open(cls.flow_log_file, 'w') as file:
            file.write("2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2 443 49153 6 25 20000 1620140761 1620140821 ACCEPT OK\n")
            file.write("2 123456789012 eni-4d3c2b1a 192.168.1.100 203.0.113.101 80 49154 6 15 12000 1620140761 1620140821 REJECT OK\n")

        cls.processor = LogAggregator(cls.lookup_file, cls.protocol_file)

    def test_load_lookup_table(self):
        self.assertEqual(self.processor.lookup_table, {(80, 'tcp'): 'web traffic', (443, 'tcp'): 'secure web traffic'})

    def test_load_protocol_numbers(self):
        self.assertEqual(self.processor.protocol_lookup, {'6': 'tcp', '17': 'udp'})

    def test_process_flow_logs(self):
        tag_count, port_protocol_count = self.processor.process_flow_logs(self.flow_log_file)
        self.assertEqual(tag_count, {'untagged': 2})
        self.assertEqual(port_protocol_count, {(49153, 'tcp'): 1, (49154, 'tcp'): 1})

    def test_save_results(self):
        tag_count = {'Secure Web Traffic': 1, 'Web Traffic': 1}
        port_protocol_count = {(443, 'tcp'): 1, (80, 'tcp'): 1}
        self.processor.save_results(tag_count, port_protocol_count, self.output_file)
        self.assertTrue(os.path.exists(self.output_file))

    def test_case_insensitivity_of_mappings(self):
        tag_count, port_protocol_count = self.processor.process_flow_logs(self.flow_log_file)
        expected_tag = 'untagged'
        self.assertIn(expected_tag, tag_count, f"Tag '{expected_tag}' should be case insensitive.")


    @classmethod
    def tearDownClass(cls):
        os.remove(cls.lookup_file)
        os.remove(cls.protocol_file)
        os.remove(cls.flow_log_file)
        os.remove(cls.output_file)

if __name__ == '__main__':
    unittest.main()