EvilAP_Defender is an application that helps wireless network administrator to discover and prevent Evil Access Points (AP) from attacking wireless users.
The application can be run in regular intervals to protect your wireless network from Evil Twin like attacks. 
By configuring the tool you can get notifications sent to your email whenever an evil access point is discovered.
Additionally you can configure the tool to perform DoS on discovered evil AP in order to give the administrator more time to react.
However, notice that the DoS will only be performed for evil APs which have the same SSID but different BSSID (AP’s MAC address) or running on a different channel. This to avoid DoS your legitimate network.

The tool is able to discover evil APs using one of the following characteristics:
  * Evil AP with a different BSSID address
  * Evil AP with the same BSSID as the legitimate AP but a different attribute (including: channel, cipher, privacy protocol, and authentication)
  * Evil AP with the same BSSID and attributes as the legitimate AP but different tagged parameter - mainly different OUI (tagged parameters are additional values sent along with the beacon frame. Currently no software based AP gives the ability to change these values. Generally software based APs are so poor in this area). 

Whenever an Evil AP is discovered the tool will alert the admin through email (SMS will be supported soon). Additionally the tool will enter into preventive mode in which the tool will DoS the discovered Evil AP.
The tool can be configured easily by starting in what we call “Learning Mode”. In this mode you can whitelist your legitimate network. This can be done by following the wizards during the Learning Mode. You can also configure the preventive mode and admin notification from there as well.
Finally, you need to change into Normal Mode or re-run the tool in this mode in order to start discovering Evil APs.

Requirements:
  - Aircrack-ng suite
  - Your wireless card must be supported by Aircrack-ng. Check the following URL: http://www.aircrack-ng.org/doku.php?id=compatibility_drivers#which_is_the_best_card_to_buy
  - MySQL
  - Python

Learning Mode:
This Mode can be invoked with the “-L” switch. When running the tool in this mode the tool will start by scanning for the available wireless networks. Then it lists all the found wireless networks with whitelisted APs colored with green. It also lists the whitelist APs and OUIs (tagged parameters). 
The tool also provides several options which allow you to add/remove SSIDs into/from whitelist. You need to whitelist your SSID first before running the tool in the Normal Mode. Moreover, you can configure Preventive Mode from “Update options -> Configure Preventive Mode”. First you need to set the Deauthentication time (in seconds) into a number bigger than 0 (setting the value to 0 will disable this mode).  Then you need to set the number of time to repeat the attack. This is so important for attacking more than Evil AP because the tool cannot attack all of them in the same time (how can you attack several APs on different channels? Later on we will improve the tool and allow it to attack (in the same time) several APs in the same channel). The tool will attack the first Evil AP for specified deauthentication time then it will stop and attack the second one and so on. Be careful from increasing the Deatuth time so much because this may attack only one AP and leaving the others running. My recommendation is to set the Deauth time to something suitable such as 10 seconds and increasing the repeat time. Finally, you can configure admin notification by setting admin email, SMPT server address, SMTP username (complete email address) for authentication purpose, and SMTP password. You can use any account on Gmail or your internal SMTP server account.

Normal Mode:
This is the mode in which the tool starts to discover Evil APs and notify the administrator whenever one is discovered. This mode can be invoked by “-N” switch.

Feedback:
Feedback is always welcomed on the tool git or through my email: moha99sa at yahoo dot com.
