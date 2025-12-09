## **totally FREE and uses ZERO resources while idle, just a tiny spike of CPU while scanning**


### The program was packaged with PyInstaller, which often triggers false positives, so the VirusTotal results below are not an actual threat. There’s nothing to worry about, the exe was generated directly from the project using PyInstaller, and the full Python code is included in the repo, so you can review it yourself and confirm that there’s nothing malicious.
### VirusTotal Scan: [https://www.virustotal.com/gui/file/c093519cabeb9d3cff93d94013fc26daf9fca3696249f83bcdd0bdaa3373300a](https://www.virustotal.com/gui/file/da28188046d5bc901e3f77430c539baeaebeb1f1f723c031028cbf15b29f54a7)

<p float="left">
  <img src="https://github.com/user-attachments/assets/a588ebb7-5703-42b0-bd47-a07dd564c013" width="35%" />
  <img src="https://github.com/user-attachments/assets/fd7ba647-441c-4240-8d21-a0eb614e875f" width="40%" />
</p>

# **VirusTotal Background Scanner**
A small Python script that runs in the background and automatically checks new downloaded files using VirusTotal.

## **Usage**
**Open the dashboard using the tray icon**

**Double click the file name texts in the dashboard list to open its VirusTotal results page. You can also double click any other text or info to copy it, or just right click to access these options and more.**

## **Setup**
Install the EXE, save it wherever you prefer, and run it.

## **How It Works**
Once running, the script stays in the background and:
* Watches for newly created or modified files inside /Downloads folder
* Sends file hashes (or files) to VirusTotal
* Waits for the report and reads the detection count
* Shows a small Windows notification with the result
* Updates the dashboard (open the dashboard using the tray icon)

It basically handles the VirusTotal checking for you, automatically, without getting in the way.
