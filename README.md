# **VirusTotal Background Scanner**
A small Python script that runs in the background and automatically checks new files with VirusTotal.

**open the dashboard using the tray icon**

## **Setup**
### **1. Install Python**
Make sure Python 3.x is installed.

### **2. Get Your VirusTotal API Key**
Get your key here:
[https://www.virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey)

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
