## **totally FREE and uses ZERO resources while idle, just a tiny spike of CPU while scanning**


### The program was packaged with PyInstaller, which often triggers false positives, so the VirusTotal results below are not an actual threat. There’s nothing to worry about, the exe was generated directly from the project using PyInstaller, and the full Python code is included in the repo, so you can review it yourself and confirm that there’s nothing malicious.
### .pyw file VirusTotal Scan: https://www.virustotal.com/gui/file/9d4b0e6d88331c6a0891047a4e22a5b0e577912fd1ad42e45add77ccb398bf82
### .exe file VirusTotal Scan: https://www.virustotal.com/gui/file/158fa338e1b6022457699fdc74879fb3ec949a8961ddedb75e555ce5a5abbe38

<p float="left">
  <img src="https://github.com/user-attachments/assets/a588ebb7-5703-42b0-bd47-a07dd564c013" width="35%" />
  <img src="https://github.com/user-attachments/assets/fd7ba647-441c-4240-8d21-a0eb614e875f" width="40%" />
</p>

# **VirusTotal Background Scanner**
A small Python script that runs in the background and automatically checks new downloaded files using VirusTotal.

## **Usage**
##**Open the dashboard using the tray icon**
## **Right click the tray icon or any text in the dashboard to access additional options. You can also left double click on the texts for quick actions.**

## **Setup**
Install the EXE, save it wherever you prefer, and run it.

## **How It Works**
Once running, the script stays in the background and:
* Watcher: It sits quietly in your system tray and keeps an eye on your Downloads folder.
* Instant Check: When a new file arrives, it immediately checks its digital fingerprint (hash) against VirusTotal.
* Save Your Credits: To prevent hitting API limits, files with unknown hashes inside folders aren't uploaded automatically. You choose exactly what to scan by clicking [ Analyze ].
* Privacy Mode: You can enable Hash-Only Mode to block all uploads of unknown hashes. This ensures the tool only checks for existing results and never sends your files to the cloud.
* Real-Time Alerts: You get a desktop notification the moment a scan is finished or a threat is detected.
* Always Ready: You can toggle Run on Startup so you don't have to launch it manually every time (right click on the tray icon).

It basically handles the VirusTotal checking for you, automatically, without getting in the way.
