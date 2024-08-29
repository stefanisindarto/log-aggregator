import random
import csv

# Define the possible protocols and tags
protocols = ['tcp', 'udp', 'icmp']
tags = ['sv_P1', 'sv_P2', 'sv_P3', 'sv_P4', 'sv_P5', 'email']

def random_port():
    return random.randint(1, 65535)

def random_protocol():
    return random.choice(protocols)

def random_tag():
    return random.choice(tags)


lookup_table_entries = []

# Generate 10,000 lookup table entries
for _ in range(10000):
    entry = (
        random_port(),  # dstport
        random_protocol(),  # protocol
        random_tag()  # tag
    )
    lookup_table_entries.append(entry)

# Write the lookup table to a CSV file
with open("lookup_table.csv", "w", newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["dstport", "protocol", "tag"])
    for entry in lookup_table_entries:
        writer.writerow(entry)

print("Lookup table created successfully.")
