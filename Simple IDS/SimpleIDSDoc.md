## SimpleIDS Documentation

### Overview
The SimpleIDS script is an Intrusion Detection System (IDS) implemented in Python using the Scapy library. It monitors network traffic for potential port scans and SQL injection attempts based on predefined rules.

### Features
1. Detection of potential port scans.
2. Detection of SQL injection attempts.
3. Real-time alerting for detected suspicious activity.

### Usage
1. **Prerequisites**: Ensure you have Python and the Scapy library installed on your system.
   
2. **Running the Script**: Execute the script `simpleIDS.py` using Python:

```python3
python simpleIDS.py
```

3. **Monitoring Network Traffic**: The IDS will start capturing network packets and analyzing them against predefined rules.

4. **Alerting**: Whenever suspicious activity is detected, the IDS will print alert messages to the console, indicating the type of activity and relevant details such as source and destination IP addresses.

### Customization
You can customize the IDS by modifying the following aspects:
- Detection rules: Update the predefined rules or add new rules to match specific patterns of suspicious activity.
- Alerting mechanism: Modify the alert messages or integrate with other notification systems as needed.

### Example Usage
- Monitoring a network during penetration testing or security assessments.
- Analyzing network traffic for potential security threats in real-time.
