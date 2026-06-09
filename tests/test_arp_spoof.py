# this file needs to contain tests for 3 main things : 
# 1. the MAC table is updated correctly when new ARP packets are captured
# 2. an alert is raised when a MAC address associated with an IP address changes
# 3. no alert is raised when a MAC address associated with an IP address does not change
# 4. edge case - ARP request not reply - ignored completely and no changes in the ARP table