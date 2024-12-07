import pandas as pd
import re
from collections import defaultdict

file_path = r'C:\Users\madha\Desktop\sample.log'
data = pd.read_csv(file_path, sep='delimiter', header=None, engine='python')

# Regex pattern to extract IP address, endpoint, and status code from the log file
log_pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+) .*? "\w+ (?P<endpoint>.*?) HTTP/.*?" (?P<status>\d{3})'

SuspiciousActivity = defaultdict(int)
RequestsPerIp = defaultdict(int)
AccessedEndPoints = defaultdict(int)
threshold = 10  # Threshold for Suspicious Activity

for i in data[0]:
    # Checking if the log file matches the regex pattern
    match = re.match(log_pattern, i)

    if match:
        IpAddress = match.group('ip')
        Endpoint = match.group('endpoint')
        Status = match.group('status')

        RequestsPerIp[IpAddress] += 1
        AccessedEndPoints[Endpoint] += 1
        if Status == '401':
            SuspiciousActivity[IpAddress] += 1



# Printing required information

print("IP Address".ljust(20) + "Request Count")
print("-" * 35)
for key, value in RequestsPerIp.items():
    print(f"{key.ljust(20)}{str(value).rjust(15)}")


most_frequent_endpoint = max(AccessedEndPoints, key=AccessedEndPoints.get)
max_value = AccessedEndPoints[most_frequent_endpoint]
print("\nMost Frequently Accessed Endpoint:")
print(f"{most_frequent_endpoint} (Accessed {max_value} times)")


print("\nSuspicious Activity Detected:")
print("IP Address".ljust(20) + "Failed Login Attempts")
print("-" * 35)
for key, value in SuspiciousActivity.items():
    if value > threshold:
        print(f"{key.ljust(20)}{str(value).rjust(15)}")



# Prepare data for CSV output
requests_per_ip_df = pd.DataFrame(
    [{"Category": "Requests per IP", "IP Address": ip, "Request Count": count} for ip, count in RequestsPerIp.items()]
)

most_accessed_endpoint = max(AccessedEndPoints, key=AccessedEndPoints.get)
most_accessed_df = pd.DataFrame(
    [{"Category": "Most Accessed Endpoint", "Endpoint": most_accessed_endpoint, "Access Count": AccessedEndPoints[most_accessed_endpoint]}]
)

suspicious_activity_df = pd.DataFrame(
    [{"Category": "Suspicious Activity", "IP Address": ip, "Failed Login Count": count} for ip, count in SuspiciousActivity.items() if count > threshold]
)

blank_row = pd.DataFrame([{"Category": "", "IP Address": "", "Request Count": ""}])  # Add blank columns for alignment
final_df = pd.concat([requests_per_ip_df, blank_row, most_accessed_df, blank_row, suspicious_activity_df], ignore_index=True)



# Save to a CSV file
output_file = r'C:\Users\madha\Desktop\log_analysis_results.csv'
final_df.to_csv(output_file, index=False)
