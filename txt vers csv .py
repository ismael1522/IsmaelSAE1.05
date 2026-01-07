import csv
import re
import os

# Set working directory to the script's location
os.chdir(os.path.dirname(os.path.abspath(__file__)))

def generate_clean_csv():
    """Reads DumpFile.txt and extracts IP traffic into a CSV file."""
    try:
        with open('DumpFile.txt', 'r') as f:
            lines = f.readlines()

        with open('DumpFile.csv', 'w', newline='') as csv_file:
            writer = csv.writer(csv_file, delimiter=';')
            # Header row
            writer.writerow(['Timestamp', 'Source', 'Destination', 'Packet_Info'])

            for line in lines:
                # We only process lines containing "IP" headers
                if "IP" in line:
                    elements = line.split()
                    
                    timestamp = elements[0]
                    source = elements[2]
                    # Remove trailing colon from destination
                    destination = elements[4].replace(':', '')
                    # Join the remaining parts as packet details
                    packet_details = " ".join(elements[5:])
                    
                    writer.writerow([timestamp, source, destination, packet_details])
        
        print("Success: DumpFile.csv file created!")
    
    except FileNotFoundError:
        print("Error: DumpFile.txt not found. Please check the file path.")

if __name__ == "__main__":
    generate_clean_csv()