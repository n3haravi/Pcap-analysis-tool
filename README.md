Overview

This project is a PCAP (Packet Capture) analysis tool that replicates the core packet-dissection and traffic-analysis logic of Wireshark in a simplified, programmatic way.
It reads PCAP files, decodes network packets, extracts protocol-level information, and provides insights into network traffic behavior.

Instead of using Wireshark as a black box, this project focuses on understanding and implementing how packet analysis works internally.

Objectives

Understand the structure of PCAP files

Decode network protocols programmatically

Analyze captured network traffic

Replicate core Wireshark analysis logic for learning purposes



Features

Load and analyze PCAP files

Decode packet layers:

Ethernet

IP

TCP / UDP / ICMP

Extract key packet details:

Source & destination IP

Source & destination ports

Protocol type

Packet length

Basic traffic analysis:

Protocol distribution

Packet counts

Communication patterns




How This Replicates Wireshark

This project replicates Wireshark’s core logic, including:

Reading PCAP binary data

Dissecting packets layer by layer

Applying programmatic filters

Analyzing network flows

Note: This is not a full Wireshark clone, but a learning-focused implementation of its internal packet-analysis concepts.




Tech Stack

Language: Python

Libraries:

Scapy (packet parsing & analysis)

Environment: Debian Linux
