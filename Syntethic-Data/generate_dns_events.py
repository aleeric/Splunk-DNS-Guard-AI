import datetime
import ipaddress
import json
import random
import string
import time
from collections import Counter

# --- CONFIGURATION ---

# General Settings
TOTAL_EVENTS = 500000
TIME_RANGE_DAYS = 90
OUTPUT_FILE = "dns_events.json"

# Environment Settings
NUM_WINDOWS_PCS = 80
NUM_LINUX_SERVERS = 20
DESKTOP_SUBNET = "192.168.1.0/24"
SERVER_SUBNET = "10.10.0.0/16"
DNS_SERVER_IP = "8.8.8.8"  # External DNS resolver

# Legitimate Domains (Top ~50 for variety)
LEGITIMATE_DOMAINS = [
    "google.com",
    "youtube.com",
    "facebook.com",
    "twitter.com",
    "instagram.com",
    "baidu.com",
    "wikipedia.org",
    "yahoo.com",
    "amazon.com",
    "live.com",
    "zoom.us",
    "reddit.com",
    "netflix.com",
    "microsoft.com",
    "office.com",
    "linkedin.com",
    "stackoverflow.com",
    "github.com",
    "apple.com",
    "windowsupdate.com",
    "dropbox.com",
    "bing.com",
    "wordpress.org",
    "adobe.com",
    "spotify.com",
    "twitch.tv",
    "ebay.com",
    "pinterest.com",
    "salesforce.com",
    "cnn.com",
    "nytimes.com",
    "theguardian.com",
    "espn.com",
    "weather.com",
    "walmart.com",
    "craigslist.org",
    "imdb.com",
    "paypal.com",
    "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "homedepot.com",
    "lowes.com",
    "target.com",
    "slack.com",
    "sharepoint.com",
    "ubuntu.com",
    "centos.org",
    "redhat.com",
    "docker.com",
    "kubernetes.io",
    "ntp.org",
]

# Anomaly Settings
ANOMALY_DOMAINS = {
    "TXT_RECORD": "data-exfiltration.xyz",
    "ANY_RECORD": "broad-queries.xyz",
    "HINFO_RECORD": "host-info-leakage.xyz",
    "AXFR_RECORD": "zone-transfer.xyz",
    "QUERY_LENGTH": "long-malicious-domain.xyz",
    "HIGH_QUERIES": "c2-tunneling.xyz",
    "HIGH_SUBDOMAINS": "domain-shadowing.xyz",
    "BEACONING": "beaconing.xyz",
}

# --- HELPER FUNCTIONS ---


def generate_ip_list(count, subnet_str):
    """Generates a list of unique IP addresses from a given subnet."""
    network = ipaddress.ip_network(subnet_str)
    ips = []
    # Ensure we don't request more IPs than available in the subnet
    max_ips = min(
        count, network.num_addresses - 2
    )  # Exclude network and broadcast addresses
    for i, ip in enumerate(network.hosts()):
        if i >= max_ips:
            break
        ips.append(str(ip))
    return ips


def get_random_timestamp(start_date, end_date, is_desktop=False):
    """
    Generates a random timestamp within the date range.
    If it's a desktop, biases towards business hours (Mon-Fri, 8am-6pm).
    """
    delta = end_date - start_date
    random_seconds = random.randint(0, int(delta.total_seconds()))
    ts = start_date + datetime.timedelta(seconds=random_seconds)

    if is_desktop:
        # If outside business hours, try to shift it into business hours
        while ts.weekday() >= 5 or not (8 <= ts.hour < 18):
            # Move to the next day's business hours start
            if ts.hour >= 18:
                ts += datetime.timedelta(days=1)
                ts = ts.replace(hour=8, minute=random.randint(0, 59))
            else:  # Before 8am
                ts = ts.replace(hour=8, minute=random.randint(0, 59))
            # If it falls on a weekend, move to Monday
            if ts.weekday() >= 5:
                ts += datetime.timedelta(days=(7 - ts.weekday()))
                ts = ts.replace(hour=random.randint(8, 17))

    # Ensure timestamp is not in the future
    if ts > end_date:
        return end_date

    return ts


def create_base_event(timestamp, src_ip, query, record_type):
    """Creates a dictionary representing a DNS event with CIM fields."""
    reply_code = "No Error"
    answer = str(ipaddress.ip_address(random.randint(1, 0xFFFFFFFF)))
    if random.random() < 0.05:  # 5% chance of NXDomain
        reply_code = "NXDomain"
        answer = ""

    event_time_str = timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    return {
        "_time": event_time_str,
        "vendor_product": "Splunk-DNS-Guard-AI",
        "query": query,
        "record_type": record_type,
        "src": src_ip,
        "dest": DNS_SERVER_IP,
        "src_port": random.randint(49152, 65535),
        "dest_port": 53,
        "transport": "udp" if record_type != "AXFR" else "tcp",
        "transaction_id": hex(random.randint(0, 65535)),
        "reply_code": reply_code,
        "reply_code_id": 0 if reply_code == "No Error" else 3,
        "answer": answer if answer else None,
        "answer_count": 1 if answer else 0,
        "query_count": 1,
        "additional_answer_count": random.randint(0, 2),
        "authority_answer_count": random.randint(1, 4),
        "duration": round(random.uniform(0.001, 0.15), 6),
        "response_time": round(random.uniform(0.001, 0.15), 6),
        "ttl": random.randint(30, 3600),
        "message_type": "response",
        # Placeholder fields
        "dest_bunit": "External",
        "dest_category": "Internet",
        "dest_priority": "low",
        "name": "DNS_Traffic_Simulation",
        "src_bunit": "Corporate",
        "src_category": "Workstations" if "192.168" in src_ip else "Servers",
        "src_priority": "medium",
        "tag": "network",
    }


def generate_random_subdomain(length=20):
    """Generates a random string to be used as a subdomain."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


# --- ANOMALY GENERATION FUNCTIONS ---


def inject_simple_record_anomaly(
    events, victims, domain, record_type, count_per_pc, days, end_time
):
    """Generic injector for TXT, ANY, HINFO, AXFR anomalies."""
    print(f"  Injecting {record_type} anomaly for domain '{domain}'...")
    start_time = end_time - datetime.timedelta(days=days)
    for victim in victims:
        for _ in range(count_per_pc):
            ts = get_random_timestamp(start_time, end_time, is_desktop=True)
            event = create_base_event(ts, victim["ip"], domain, record_type)
            # Override some fields for specific anomalies
            if record_type == "TXT":
                event["answer"] = "v=spf1 include:_spf.google.com ~all"
            elif record_type == "ANY":
                event["answer_count"] = random.randint(
                    5, 15
                )  # ANY returns multiple records
            events.append(event)


def inject_query_length_anomaly(events, victim, domain, count, days, end_time):
    """Injects queries with very long subdomains."""
    print(f"  Injecting Query Length anomaly for domain '{domain}'...")
    start_time = end_time - datetime.timedelta(days=days)
    for _ in range(count):
        ts = get_random_timestamp(start_time, end_time, is_desktop=True)
        long_subdomain = generate_random_subdomain(random.randint(40, 80))
        query = f"{long_subdomain}.{domain}"
        event = create_base_event(ts, victim["ip"], query, "A")
        events.append(event)


def inject_high_queries_anomaly(events, victims, domain, count_per_pc, days, end_time):
    """Injects a high volume of queries in a short time (burst)."""
    print(f"  Injecting High Query Count (C2) anomaly for domain '{domain}'...")
    # The attack happens within a random 1-day window in the last week
    attack_day_start = end_time - datetime.timedelta(days=random.randint(days, 7))
    attack_day_end = attack_day_start + datetime.timedelta(days=1)

    for victim in victims:
        for _ in range(count_per_pc):
            # Compress timestamps into a few hours to simulate a burst
            burst_start = attack_day_start.replace(hour=random.randint(9, 15))
            burst_end = burst_start + datetime.timedelta(hours=2)
            ts = get_random_timestamp(burst_start, burst_end, is_desktop=True)
            event = create_base_event(ts, victim["ip"], domain, "A")
            events.append(event)


def inject_high_subdomains_anomaly(
    events, victim, domain, total_queries, num_subdomains, days, end_time
):
    """Injects queries to many different subdomains of a single domain."""
    print(f"  Injecting High Subdomain (Shadowing) anomaly for domain '{domain}'...")
    start_time = end_time - datetime.timedelta(days=days)
    subdomains = [
        generate_random_subdomain(random.randint(4, 12)) for _ in range(num_subdomains)
    ]
    for _ in range(total_queries):
        ts = get_random_timestamp(start_time, end_time, is_desktop=True)
        query = f"{random.choice(subdomains)}.{domain}"
        event = create_base_event(ts, victim["ip"], query, "A")
        events.append(event)


def inject_beaconing_anomaly(events, victims, domain, count_per_pc, days, end_time):
    """Injects queries at very regular intervals."""
    print(f"  Injecting Beaconing anomaly for domain '{domain}'...")
    # Use consistent intervals like 30, 60, or 120 minutes
    interval = datetime.timedelta(minutes=random.choice([30, 60, 120]))

    for victim in victims:
        # Start beaconing at a random time within the attack window
        attack_window_start = end_time - datetime.timedelta(days=days)
        current_beacon_time = get_random_timestamp(
            attack_window_start, end_time - datetime.timedelta(days=1)
        )
        for _ in range(count_per_pc):
            if current_beacon_time > end_time:
                break
            # Add a small random jitter to make it slightly less robotic
            jitter = datetime.timedelta(seconds=random.randint(-30, 30))
            event = create_base_event(
                current_beacon_time + jitter, victim["ip"], domain, "A"
            )
            events.append(event)
            current_beacon_time += interval


# --- MAIN SCRIPT ---


def main():
    start_timer = time.time()
    print("--- DNS Event Generator for Splunk CIM ---")

    # 1. Setup Environment
    print("\n[1/5] Setting up virtual environment...")
    windows_ips = generate_ip_list(NUM_WINDOWS_PCS, DESKTOP_SUBNET)
    linux_ips = generate_ip_list(NUM_LINUX_SERVERS, SERVER_SUBNET)

    windows_pcs = [{"ip": ip, "type": "windows"} for ip in windows_ips]
    linux_servers = [{"ip": ip, "type": "linux"} for ip in linux_ips]
    all_machines = windows_pcs + linux_servers

    print(
        f"  Created {len(windows_pcs)} Windows desktops and {len(linux_servers)} Linux servers."
    )

    events = []
    end_time = datetime.datetime.now(datetime.timezone.utc)
    start_time = end_time - datetime.timedelta(days=TIME_RANGE_DAYS)

    # 2. Inject Anomalous Events
    print("\n[2/5] Injecting anomalous DNS activities...")
    # To ensure different anomalies affect different PCs, we create separate victim pools
    victim_pool = random.sample(
        windows_pcs, k=25
    )  # get a large enough pool of potential victims

    # TXT Record Anomaly
    inject_simple_record_anomaly(
        events,
        random.sample(victim_pool, 3),
        ANOMALY_DOMAINS["TXT_RECORD"],
        "TXT",
        2000,
        7,
        end_time,
    )
    # ANY Record Anomaly
    inject_simple_record_anomaly(
        events,
        random.sample(victim_pool, 3),
        ANOMALY_DOMAINS["ANY_RECORD"],
        "ANY",
        2000,
        7,
        end_time,
    )
    # HINFO Record Anomaly
    inject_simple_record_anomaly(
        events,
        random.sample(victim_pool, 3),
        ANOMALY_DOMAINS["HINFO_RECORD"],
        "HINFO",
        2000,
        7,
        end_time,
    )
    # AXFR Record Anomaly
    inject_simple_record_anomaly(
        events,
        random.sample(victim_pool, 3),
        ANOMALY_DOMAINS["AXFR_RECORD"],
        "AXFR",
        2000,
        7,
        end_time,
    )
    # Query Length Anomaly
    inject_query_length_anomaly(
        events,
        random.choice(victim_pool),
        ANOMALY_DOMAINS["QUERY_LENGTH"],
        50,
        4,
        end_time,
    )
    # High Query Count Anomaly
    inject_high_queries_anomaly(
        events,
        random.sample(victim_pool, 10),
        ANOMALY_DOMAINS["HIGH_QUERIES"],
        10000,
        1,
        end_time,
    )
    # High Subdomain Anomaly
    inject_high_subdomains_anomaly(
        events,
        random.choice(victim_pool),
        ANOMALY_DOMAINS["HIGH_SUBDOMAINS"],
        2000,
        200,
        1,
        end_time,
    )
    # Beaconing Anomaly
    inject_beaconing_anomaly(
        events,
        random.sample(victim_pool, 5),
        ANOMALY_DOMAINS["BEACONING"],
        2000,
        14,
        end_time,
    )

    num_anomaly_events = len(events)
    print(f"  Total anomalous events generated: {num_anomaly_events}")

    # 3. Generate Legitimate Traffic
    print("\n[3/5] Generating legitimate DNS traffic...")
    num_legit_events = TOTAL_EVENTS - num_anomaly_events

    record_type_weights = {
        "A": 0.55,
        "AAAA": 0.35,
        "MX": 0.04,
        "PTR": 0.03,
        "CNAME": 0.02,
        "NS": 0.01,
    }
    record_types = list(record_type_weights.keys())
    weights = list(record_type_weights.values())

    for i in range(num_legit_events):
        # Servers are more active 24/7, so give them a slightly higher chance of being picked
        machine = random.choice(
            all_machines if random.random() > 0.2 else linux_servers
        )

        is_desktop = machine["type"] == "windows"
        ts = get_random_timestamp(start_time, end_time, is_desktop)

        query = random.choice(LEGITIMATE_DOMAINS)
        record_type = random.choices(record_types, weights, k=1)[0]

        event = create_base_event(ts, machine["ip"], query, record_type)
        events.append(event)

        if (i + 1) % 50000 == 0:
            print(f"  ...generated {i+1}/{num_legit_events} legitimate events.")

    print(f"  Total legitimate events generated: {num_legit_events}")

    # 4. Finalize and Write to File
    print("\n[4/5] Shuffling and writing events to file...")
    random.shuffle(events)

    # Store the original dictionaries before modification for the summary
    original_events_for_summary = [e.copy() for e in events]

    with open(OUTPUT_FILE, "w") as f:
        # For Splunk, it's often best to have one JSON object per line.
        # This loop creates a flat JSON structure.
        for event in events:
            # Rename '_time' to 'time' for Splunk and add other metadata fields
            event["timestamp"] = event.pop("_time")

            f.write(json.dumps(event) + "\n")

    print(f"  Successfully wrote {len(events)} events to '{OUTPUT_FILE}'.")

    # 5. Print Summary
    print("\n[5/5] --- Generation Summary ---")
    total_time = time.time() - start_timer

    # Use the unmodified copy for accurate summary statistics
    record_type_counts = Counter(e["record_type"] for e in original_events_for_summary)

    # Correctly count anomaly domains, even with varying subdomains.
    domain_counts = Counter()
    anomaly_base_domains = set(ANOMALY_DOMAINS.values())
    for e in original_events_for_summary:
        query = e.get("query", "")  # Use .get for safety
        for base_domain in anomaly_base_domains:
            if query.endswith(base_domain):
                domain_counts[base_domain] += 1
                break  # Count each event only once, for its base malicious domain

    print(f"\nExecution Time: {total_time:.2f} seconds")
    print(f"Total Events Generated: {len(events):,}")
    print(
        f"Time Range: {start_time.strftime('%Y-%m-%d')} to {end_time.strftime('%Y-%m-%d')}"
    )
    print("-" * 30)
    print("Event Breakdown:")
    print(f"  - Legitimate Events: {num_legit_events:,}")
    print(f"  - Anomalous Events:  {num_anomaly_events:,}")
    print("-" * 30)
    print("Record Type Distribution:")
    for r_type, count in record_type_counts.most_common():
        print(f"  - {r_type:<10}: {count:>8,}")
    print("-" * 30)
    print("Anomaly Domain Query Counts:")
    for domain, count in sorted(domain_counts.items()):
        print(f"  - {domain:<28}: {count:>8,}")
    print("\n--- Generation Complete ---")


if __name__ == "__main__":
    main()
