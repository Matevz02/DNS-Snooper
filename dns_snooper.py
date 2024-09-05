import csv
import subprocess
import time
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

def dig_query(ip, domain="google.com", current=None, total=None):
    """
    Uses the 'dig' command to query the specified IP address for the given domain.
    Returns True if the query is successful, False otherwise.
    """
    print(f"({current}/{total}) dig@{ip} {domain}")
    try:
        result = subprocess.run(
            ["dig", f"@{ip}", domain], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE
        )
        if "NOERROR" in result.stdout.decode('utf-8'):
            print(f"({current}/{total}) {ip} anwsered")
            return True
        else:
            print(f"({current}/{total}) {ip} didn't anwser")
            return False
    except Exception as e:
        print(f"({current}/{total}) Error performing dig for {ip}: {e}")
        return False

def nslookup_query(ip, current=None, total=None):
    """
    Uses the 'nslookup' command to query the specified IP address.
    Returns the result (domain name or error message) as a string.
    """
    print(f"({current}/{total}) nslookup {ip}...")
    try:
        result = subprocess.run(
            ["nslookup", ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        output = result.stdout.decode('utf-8')
        if "name =" in output:
            domain = output.split("name =")[1].split()[0].strip('.')
            print(f"({current}/{total}) nslookup successful for {ip}: {domain}")
            return domain
        else:
            print(f"({current}/{total}) nslookup failed for {ip}")
            return "no domain found"
    except Exception as e:
        print(f"({current}/{total}) Error performing nslookup for {ip}: {e}")
        return "error"

def read_ips_from_csv(csv_file):
    """
    Reads IP addresses from a CSV file. Returns the list of rows including headers.
    """
    print(f"Reading IP addresses from {csv_file}...")
    rows = []
    with open(csv_file, 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            rows.append(row)
    print(f"Found {len(rows) - 1} IP addresses (excluding header).")
    return rows

def write_results_to_csv(rows, results, output_file):
    """
    Writes the original rows and the results of the dig and nslookup queries to a new CSV file.
    """
    print(f"Writing results to {output_file}...")
    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)
        # Write headers, append "Status" and "Domain" columns
        writer.writerow(rows[0] + ["Status", "Domain"])
        
        # Write each row with dig and nslookup results
        for row in rows[1:]:
            ip = row[0]
            dig_status = "public" if results[ip]["dig"] else "private"
            domain = results[ip]["nslookup"]
            writer.writerow(row + [dig_status, domain])
            print(f"Wrote result for IP: {ip} -> Status: {dig_status}, Domain: {domain}")
    print(f"Finished writing to {output_file}.")

def write_results_to_txt(results, output_txt):
    """
    Writes the dig and nslookup results to a text file in a human-readable format.
    """
    print(f"Writing results to {output_txt}...")
    with open(output_txt, 'w') as file:
        for ip, result in results.items():
            dig_status = "public" if result["dig"] else "private"
            domain = result["nslookup"]
            file.write(f"IP: {ip}, Status: {dig_status}, Domain: {domain}\n")
            print(f"Wrote result for IP: {ip} -> Status: {dig_status}, Domain: {domain}")
    print(f"Finished writing to {output_txt}.")

def main(input_csv, output_csv, output_txt):
    start_time = time.time()
    rows = read_ips_from_csv(input_csv)
    
    # Extract IPs from the rows (assuming they are in the first column)
    ips = [row[0] for row in rows[1:]]  # Skip header row
    total_ips = len(ips)  # Get total number of IPs for progress tracking
    
    # Dictionary to hold results for each IP address (key: IP, value: dict with dig and nslookup results)
    results = {ip: {"dig": None, "nslookup": None} for ip in ips}
    
    # Use ThreadPoolExecutor for parallel execution, with 16 workers (threads)
    print(f"Starting multithreaded querying with 16 threads...")
    with ThreadPoolExecutor(max_workers=16) as executor:
        future_to_ip_dig = {executor.submit(dig_query, ip, current=i+1, total=total_ips): ip for i, ip in enumerate(ips)}
        future_to_ip_nslookup = {executor.submit(nslookup_query, ip, current=i+1, total=total_ips): ip for i, ip in enumerate(ips)}
        
        # Collect dig results
        for future in as_completed(future_to_ip_dig):
            ip = future_to_ip_dig[future]
            results[ip]["dig"] = future.result()  # Get the result from dig_query
            
        # Collect nslookup results
        for future in as_completed(future_to_ip_nslookup):
            ip = future_to_ip_nslookup[future]
            results[ip]["nslookup"] = future.result()  # Get the result from nslookup_query
    
    # Write results to CSV and TXT files
    write_results_to_csv(rows, results, output_csv)
    write_results_to_txt(results, output_txt)
    
    end_time = time.time()
    print(f"Script completed in {end_time - start_time:.2f} seconds.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Perform dig and nslookup queries on IPs from a CSV file.")
    parser.add_argument("input_csv", help="Input CSV file containing IP addresses")
    parser.add_argument("-c", "--output_csv", default="results.csv", help="Output CSV file (default: results.csv)")
    parser.add_argument("-t", "--output_txt", default="results.txt", help="Output TXT file (default: results.txt)")
    
    args = parser.parse_args()
    
    main(args.input_csv, args.output_csv, args.output_txt)

