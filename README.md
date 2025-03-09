# DoS Attack Detection

This project implements a DoS (Denial of Service) attack detection system using machine learning. It captures network packets, extracts relevant features, and classifies them using a trained AdaBoost model.

## Features
- Captures network packets in real time
- Extracts key features from TCP and UDP packets
- Saves captured data to CSV files
- Uses an AdaBoost classifier to detect potential DoS attacks
- Provides a graphical user interface (GUI) for ease of use

## Images  

### Benign Connections  
![Benign Connections](images/benign_connections.png)  

### Network Connections Example  
![Network Connections](images/conexiones_1_alex.png)  

### Captured Data Sample  
![Captured Data](images/datos_capturados_alex.png)  


## Installation

### Requirements
- Python 3.x
- Required libraries:
  ```sh
  pip install pandas scikit-learn joblib customtkinter scapy
  ```

### Clone the Repository
```sh
git clone https://github.com/alexsto03ckel/DoS-Attack-Detection.git
cd DoS-Attack-Detection
```

## Usage

### Running the Detection System
1. Execute the main script:
   ```sh
   python FINAL_CODE.py
   ```
2. Click "Capture data" to start packet capture.
3. Click "Test Data" to classify the captured packets.
4. The GUI will display the predicted labels.

## File Structure
- `FINAL_CODE.py` - Main script for packet capture and classification.
- `adaboost_model_optimized2.joblib` - Pre-trained AdaBoost model.
- `SAMPLEFINAL.csv` - Stores captured packet features.
- `LABEL_RESULTS.csv` - Stores classification results.
- `testingdata_results.csv` - Stores test results.

## How It Works
1. Captures network packets using `scapy`.
2. Extracts features such as source port, destination port, and packet length.
3. Saves the extracted data to CSV files.
4. Uses an AdaBoost model to classify whether a packet is part of a DoS attack.
5. Displays the results in a GUI.

## Notes
- The program runs on Windows and requires administrator privileges to capture packets.
- Ensure that network adapter permissions are properly configured for `scapy`.

## Acknowledgments
This project was developed for research and educational purposes.
