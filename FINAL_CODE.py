import pandas as pd
from sklearn.preprocessing import StandardScaler
import joblib
import customtkinter
import tkinter as tk
import winreg
import csv
import os
from scapy.all import sniff, IP, TCP, UDP
from scapy.arch import windows
import shutil
count = 0
count2 = 0
fwd_pkt_count = 0
fwd_pkt_len_sum = 0
num_rows_to_overwrite = 0


customtkinter.set_appearance_mode("light")
customtkinter.set_default_color_theme("dark-blue")

root = customtkinter.CTk()
root.geometry("900x700")

captured_ips = []
captured_data = []
def open_packet_sniffer_window():
    packet_sniffer_window = tk.Toplevel(root)
    packet_sniffer_window.title("Packet Sniffer Options")
    packet_sniffer_window.geometry("400x300")

    interfaces = windows.get_windows_if_list()

    for i, interface in enumerate(interfaces):
        button_text = f"{i}. {interface['name']}"
        button = customtkinter.CTkButton(master=packet_sniffer_window, text=button_text, command=lambda iface=interface['name']: start_capture(iface))
        button.pack(pady=5, padx=10)

def start_capture(interface):
    def calculate_fwd_seg_size(pkt):
        try:
            return len(pkt.payload)
        except Exception:
            return 0

    def extract_init_fwd_win_bytes(pkt):
        try:
            if IP in pkt:
                if TCP in pkt:
                    tcp_flags = pkt[TCP].flags
                    if 'W' in tcp_flags:  # Check if Window Scale option is present
                        tcp_options_raw = pkt[TCP].options
                        for opt_type, opt_value in tcp_options_raw:
                            if opt_type == 'WScale':
                                # Extract the scale factor from the option value
                                scale_factor = opt_value
                                return pkt[TCP].window << scale_factor
                    else:
                        # If Window Scale option is not present, use the window size directly
                        return pkt[TCP].window
                elif UDP in pkt:
                    # Adjust this part based on the specific information you want to extract for UDP
                    return pkt[UDP].sport  # For example, using the source port for simplicity
        except Exception as e:
            print(f"Error processing packet: {e}")

        return 0

    def extract_fwd_seg_size_min(pkt):
        if pkt.haslayer(TCP):
            payload_size = len(pkt[TCP].payload)
            return payload_size
        elif pkt.haslayer(UDP):  # Add UDP packet processing
            payload_size = len(pkt[UDP].payload)
            return payload_size
        return 0

    fwd_pkt_count = 0

    def csvgather(pkt):
        text_widget.delete(1.0, tk.END)  # Clear the text_widget
        global fwd_pkt_count, fwd_pkt_len_sum, count
        if pkt.haslayer(IP):
            ip = pkt[IP].dst
            captured_ips.append(ip)
            init_fwd_win_bytes = 0
            if TCP in pkt:
                init_fwd_win_bytes = extract_init_fwd_win_bytes(pkt)
            elif UDP in pkt:
                init_fwd_win_bytes = extract_init_fwd_win_bytes(pkt)
            
            pkt_len = pkt.len if hasattr(pkt, 'len') else 0

            fwd_pkt_len_sum += pkt_len
            fwd_pkt_count += 1
            fwd_pkt_len_mean = fwd_pkt_len_sum / fwd_pkt_count if fwd_pkt_count > 0 else 0
            count += 1
            
            try:
                #port = getattr(pkt[TCP], 'sport', 0) if TCP in pkt else getattr(pkt[UDP], 'sport', 0)
                #if (fwd_pkt_len_mean != 0):    
                    fieldnames = ["Src Port", "Dst Port", "TotLen Fwd Pkts", "Fwd Pkt Len Mean", "Init Fwd Win Byts", "Fwd Seg Size Min"]

                    with open('SAMPLEFINAL.csv', 'a', newline='') as csvfile:
                        file_empty = os.stat('SAMPLEFINAL.csv').st_size == 0 

                        filewriter = csv.DictWriter(csvfile, fieldnames=fieldnames)

                        if file_empty:
                            filewriter.writeheader()

                        print(ip)
                        fwd_seg_size_min = extract_fwd_seg_size_min(pkt)
                        fwd_seg_size = calculate_fwd_seg_size(pkt)

                        init_fwd_win_bytes = 0
                        if TCP in pkt:
                            init_fwd_win_bytes = extract_init_fwd_win_bytes(pkt)
                        elif UDP in pkt:
                            init_fwd_win_bytes = extract_init_fwd_win_bytes(pkt)

                        src_port = getattr(pkt[TCP], 'sport', 0) if TCP in pkt else getattr(pkt[UDP], 'sport', 0)
                        dst_port = getattr(pkt[TCP], 'dport', 0) if TCP in pkt else getattr(pkt[UDP], 'dport', 0)

                        pkt_len = pkt.len if hasattr(pkt, 'len') else 0

                        fwd_pkt_len_sum += pkt_len
                        fwd_pkt_count += 1

                        fwd_pkt_len_mean = fwd_pkt_len_sum / fwd_pkt_count if fwd_pkt_count > 0 else 0
                        count += 1

                        if count >= 100:
                            # Reset the counts every 100 packets
                            fwd_pkt_len_sum = 0
                            fwd_pkt_count = 0
                            count = 0

                        filewriter.writerow({
                            'Src Port': src_port,
                            'Dst Port': dst_port,
                            'TotLen Fwd Pkts': pkt_len,
                            'Fwd Pkt Len Mean': fwd_pkt_len_mean,
                            'Init Fwd Win Byts': init_fwd_win_bytes,
                            'Fwd Seg Size Min': fwd_seg_size_min,
                        })

            except Exception as e:
                    print(f"Error processing packet: {e}")

    
    path5 = "C:\\Users\\alexs\\OneDrive\\Escritorio\\aalex\\Alex\\UPTP\\Cuarto Semestre\\Introduction to AI\\PROJECT\\CODE\\SAMPLEFINAL.csv"
    if os.path.exists(path5):
        os.remove(path5)

    for j in range(1, 5):
        cap = sniff(count=100, prn=csvgather, iface=interface)
    
    
    for ip in zip(captured_ips[1:]):
        text_widget.insert(tk.END, f"Packet captured with Source IP: {ip}\n")

        

def overwrite_bottom_rows(input_file, output_file):
    global num_rows_to_overwrite
    # Read the rows from the input CSV file and skip the first row
    with open(input_file, 'r', newline='') as infile:
        reader = csv.reader(infile)
        next(reader)  # Skip the first row
        input_rows = list(reader)

    num_rows_to_overwrite = len(input_rows)

    # Read the existing rows from the output CSV file
    with open(output_file, 'r', newline='') as outfile:
        reader = csv.reader(outfile)
        output_rows = list(reader)

    # Determine the range of rows to overwrite
    start_index = max(0, len(output_rows) - num_rows_to_overwrite)
    end_index = len(output_rows)

    # Overwrite the specified range with the rows from the input file
    output_rows[start_index:end_index] = input_rows

    # Write the modified rows back to the output CSV file
    with open(output_file, 'w', newline='') as outfile:
        writer = csv.writer(outfile)
        writer.writerows(output_rows)

def test_data():
    global num_rows_to_overwrite
    #Deleting the paths to use
    path1 = "C:\\Users\\alexs\\OneDrive\\Escritorio\\aalex\\Alex\\UPTP\\Cuarto Semestre\\Introduction to AI\\PROJECT\\CODE\\LABEL_RESULTS.csv"
    path2 = "C:\\Users\\alexs\\OneDrive\\Escritorio\\aalex\\Alex\\UPTP\\Cuarto Semestre\\Introduction to AI\\PROJECT\\CODE\\testingdata_results.csv"
    path3 = "C:\\Users\\alexs\\OneDrive\\Escritorio\\aalex\\Alex\\UPTP\\Cuarto Semestre\\Introduction to AI\\PROJECT\\CODE\\SAMPLE\\SampleTry - No Label Test.csv"

    if os.path.exists(path1):
        os.remove(path1)
    if os.path.exists(path2):
        os.remove(path2)
    if os.path.exists(path3):
        os.remove(path3)

    DataSample = "C:\\Users\\alexs\\OneDrive\\Escritorio\\aalex\\Alex\\UPTP\\Cuarto Semestre\\Introduction to AI\\PROJECT\\CODE\\SAMPLE\\SampleTry - No Label.csv"
    DataTest = "C:\\Users\\alexs\\OneDrive\\Escritorio\\aalex\\Alex\\UPTP\\Cuarto Semestre\\Introduction to AI\\PROJECT\\CODE\\SAMPLE\\SampleTry - No Label Test.csv"
    shutil.copyfile(DataSample, DataTest)


    input_csv_file = "C:\\Users\\alexs\\OneDrive\\Escritorio\\aalex\\Alex\\UPTP\\Cuarto Semestre\\Introduction to AI\\PROJECT\\CODE\\SAMPLEFINAL.csv"
    output_csv_file = "C:\\Users\\alexs\\OneDrive\\Escritorio\\aalex\\Alex\\UPTP\\Cuarto Semestre\\Introduction to AI\\PROJECT\\CODE\\SAMPLE\\SampleTry - No Label Test.csv"
    overwrite_bottom_rows(input_csv_file, output_csv_file)

    
    clf = joblib.load('adaboost_model_optimized2.joblib')

    # Load the file_to_classify
    file_to_classify = pd.read_csv("C:\\Users\\alexs\\OneDrive\\Escritorio\\aalex\\Alex\\UPTP\\Cuarto Semestre\\Introduction to AI\\PROJECT\\CODE\\SAMPLE\\SampleTry - No Label Test.csv", index_col=None)
    file_to_classify_columns = ["Src Port", "Dst Port", "TotLen Fwd Pkts", "Fwd Pkt Len Mean", "Init Fwd Win Byts", "Fwd Seg Size Min"]
    file_to_classify_dtypes = {"Src Port": int, "Dst Port": int, "TotLen Fwd Pkts": int, "Fwd Pkt Len Mean": float, "Init Fwd Win Byts": int, "Fwd Seg Size Min": int}

    # Assuming you have already trained the AdaBoost model and saved it in 'adaboost_model.joblib'
    # Load the trained AdaBoost model
    # Extract the features for the new data
    X_file_to_classify = file_to_classify[file_to_classify_columns]

    # Feature Scaling
    scaler = StandardScaler()
    scaler.fit(X_file_to_classify)  # Fit the scaler on the entire dataset
    X_file_to_classify_scaled = scaler.transform(X_file_to_classify)

    # Make predictions on the file_to_classify set
    y_pred_file_to_classify = clf.predict(X_file_to_classify_scaled)

    # Save the predicted labels to a CSV file
    predictions_df = pd.DataFrame({"Predicted_Label": y_pred_file_to_classify})
    predictions_df.to_csv("C:\\Users\\alexs\\OneDrive\\Escritorio\\aalex\\Alex\\UPTP\\Cuarto Semestre\\Introduction to AI\\PROJECT\\CODE\\testingdata_results.csv", index=False)

    # Extract the last num_rows_to_overwrite rows and save their labels to LABEL_RESULTS.csv
    label_results_df = predictions_df.tail(num_rows_to_overwrite)
    label_results_df.to_csv("C:\\Users\\alexs\\OneDrive\\Escritorio\\aalex\\Alex\\UPTP\\Cuarto Semestre\\Introduction to AI\\PROJECT\\CODE\\LABEL_RESULTS.csv", index=False)

    # Display the predicted labels in the text_widget
    text_widget.delete(1.0, tk.END)  # Clear the text_widget
    text_widget.insert(tk.END, "IP Address - Predicted Label:\n")

    # Iterate over the rows starting from the second row
    for ip, label in zip(captured_ips[1:], label_results_df['Predicted_Label'].iloc[1:]):
        text_widget.insert(tk.END, f"{ip} - {label}\n")


label = customtkinter.CTkLabel(master=root, text="DoS Attack Detection", font=("Roboto", 24))
label.pack(pady=12, padx=10)

button_sniffer = customtkinter.CTkButton(master=root, text="Capture data", command=open_packet_sniffer_window)
button_sniffer.pack(pady=12, padx=10)

button_nn = customtkinter.CTkButton(master=root, text="Test Data", command=test_data)
button_nn.pack(pady=12, padx=10)

text_widget = tk.Text(master=root, height=20, width=70, font=("Helvetica", 16))
text_widget.pack(pady=12, padx=10)

button_exit = customtkinter.CTkButton(master=root, text="Exit", command=root.destroy)
button_exit.pack(pady=12, padx=10)

root.mainloop()