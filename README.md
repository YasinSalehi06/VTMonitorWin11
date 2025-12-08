### **Uses no resources while idle, just a tiny spike of CPU while scanning and totally FREE**
## VirusTotal Scan: https://www.virustotal.com/gui/file/c093519cabeb9d3cff93d94013fc26daf9fca3696249f83bcdd0bdaa3373300a 



<p float="left">
  <img src="https://github.com/user-attachments/assets/a588ebb7-5703-42b0-bd47-a07dd564c013" width="35%" />
  <img src="https://github.com/user-attachments/assets/fd7ba647-441c-4240-8d21-a0eb614e875f" width="40%" />
</p>

# **VirusTotal Background Scanner**
A small Python script that runs in the background and automatically checks new files with VirusTotal.

## **Usage**
**Open the dashboard using the tray icon**
**Double click the file name texts in the list to open its VirusTotal results page and any other text or info to copy it**

## **Setup**
### **1. Install Python**
Make sure Python 3.x is installed.

### **2. Get Your FREE or paid VirusTotal API Key**
Get your key here:
[https://www.virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey)
```python
API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
```
Replace `"YOUR_VIRUSTOTAL_API_KEY"` with your actual API key (keep the quotes).


### **3. Download the Files**
Download:
* `VirusTotalScan.pyw`
* `requirements.txt`

### **4. Install Dependencies**
Run in CMD:
```
pip install -r requirements.txt
```

### **5. Optional: Run on Startup**
* Right-click `VirusTotalScan.pyw` → **Create Shortcut**
* Press `Win + R`, type `shell:startup`
* Move the shortcut into that folder


## **How It Works**
Once running, the script stays in the background and:
* Watches for newly created or modified files inside /Downloads folder
* Sends file hashes (or files) to VirusTotal
* Waits for the report and reads the detection count
* Shows a small Windows notification with the result
* Updates the dashboard (open the dashboard using the tray icon)

It basically handles the VirusTotal checking for you, automatically, without getting in the way.
