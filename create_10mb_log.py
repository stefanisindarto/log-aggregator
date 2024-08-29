import random

# Sample data for log entries
log_entry_template = "{} {} {} {} {} {} {} {} {} {} {} {} {} {}"

# Define ranges for randomization
protocols = [6, 17,]  # 6 = TCP, 17 = UDP
actions = ["ACCEPT", "REJECT"]
eni_ids = ["eni-0a1b2c3d", "eni-4d3c2b1a", "eni-5e6f7g8h", "eni-9h8g7f6e", "eni-7i8j9k0l",
           "eni-6m7n8o9p", "eni-1a2b3c4d", "eni-5f6g7h8i", "eni-9k10l11m", "eni-2d2e2f3g", "eni-4h5i6j7k"]

def random_ip():
    return "{}.{}.{}.{}".format(random.randint(10, 255), random.randint(0, 255), random.randint(0, 255), random.randint(1, 254))

def random_port():
    return random.randint(1, 65535)

def random_bytes():
    return random.randint(1000, 20000)

def random_packets():
    return random.randint(1, 50)

def random_timestamp():
    return random.randint(1620140000, 1620149999)

log_entries = []

for _ in range(100000):
    entry = (
        2,  # version
        "123456789012",  # account_id
        random.choice(eni_ids),  # eni_id
        random_ip(),  # srcaddr
        random_ip(),  # dstaddr
        random_port(),  # srcport
        random_port(),  # dstport
        random.choice(protocols),  # protocol
        random_packets(),  # packets
        random_bytes(),  # bytes
        random_timestamp(),  # start
        random_timestamp(),  # end
        random.choice(actions),  # action
        "OK"  # log_status
    )
    log_entries.append(entry)

with open("flow-log.log", "w") as file:
    for entry in log_entries:
        log_entry = log_entry_template.format(*entry)
        file.write(log_entry + "\n")

print("Log file created successfully.")
