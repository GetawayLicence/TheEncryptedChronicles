---
title: "From Scan to Scam: The Rising Threat of QRishing Attacks"
date: 2025-06-08
categories: ["Case Studies"] 
tags: ["QR Code", "QRishing", "Social Engineering", "Malware", "Phishing"]
toc: true
comments: true
---
# At a Glance
The weakest link in a system is usually the human factor. This is mainly perpetuated by our susceptibility to deception and manipulation, which opens up a significant vulnerability through which threat actors slip through and gain access into systems. Social engineering remains a prevalent tactic to breach a system, gaining traction by the year. 98% of cyber attacks launched in 2024 had involved social engineering in one form or another, highlighting its pervasive nature.   

But while social engineering once entailed suspicious emails or phone calls, it has branched out to encapsulate a broader range of tactics. Lately, a sneaky entry point attackers have been targeting has been the exploitation of QR codes. QRishing (or Qishing), a portmanteau of QR code and Phishing, is a stealthy approach at breaching security walls put in place. The danger lies in the invisibility, for the attack works by hiding a malicious URL within a harmless-looking QR code and allowing the public to access it. QR codes on public platforms as well as digital emails are weaponized to trick users into handing over credentials, installing malware or giving away sensitive information, often without them realizing it. With the rise of contactless interactions, the blind trust in the black and white squares have become a perfect entry point for attackers to exploit, causing QRishing to become a fast-growing tactic targeting both individuals as well as organisations with alarming effectiveness.

This entry hopes to break down the attack path of a typical QRishing attack that's gaining more traction by the day, and better prepare us with tips on how to prevent such attacks from scanning their way into our data.

# Threat Actor Profile
## Name: Adversary Groups intending to deliver payload onto victim devices 
## Known Motivations:  
- Gain unauthorized access into systems: Adversaries often exploit QR codes by incorporating malicious URLs that trick users into granting access or downloading malicious apps once clicked. This is to allow the formation  of backdoors for threat groups to enter a system and gain access via lateral movement. 
- Upload malicious code: Deliver malicious payload such as spyware, trojans or ransomware to device once user scans QR code and visits URL.
- Steal credentials, financial information or personal data: Redirect users to fake login pages or payment portals that mirror the original sites to harvest sensitive information of users.
- Conduct surveillance or track user behavior: Use URLs that can track and monitor users' location, device type and online activity and behavior. This is done so often without their knowledge to collect sensitive information on the user.

# The Attack: An Anatomy
QRishing is typically a social engineering technique part of a bigger attack with an ulterior motive, such as to infiltrate a system or to harvest login credentials of users. A QR code is a black and white patterned image that encodes a URL or link within. When users scan the QR code using their smartphones or devices, they are redirected to the encoded URL link. Threat actors exploit this by generating a malicious QR code that typically encodes a phishing URL or malicious malware payload. When a user scans these QR codes, they are either redirected to a spoofed login page targeting their credential information or a silent malicious payload may be downloaded into their devices. What makes QRishing so difficult to track is that there are multiple ways to disseminate the malicious QR, and these methods are typically very difficult to trace. For example, attackers may replace legitimate QR codes on public posters with fraudulent ones, or mask malicious QR codes in seemingly harmless mass emails and social media platforms. The general flow of the QR code attacks can be mapped as below: 

Social Engineering Attack - Format:
1. Research: At this stage, the attacker is seen to be lying low. They identify their target group, or the group of victims most likely to fall prey to their schemes, by observing the behaviours of their target audience periodically. The attacker takes note of factors such as what emails the target group normally receives, what services they commonly use and trust and what type of messages or incentives are most likely to appeal to them.
 
2. Hook: Here, the attacker is most focused on ensuring their intended victims will successfully scan the malicious QR codes and fall prey to their schemes. The attacker packs their malicious URL or payload into a QR code and embeds it in a platform that feels trustworthy to the victims. Typically, the QR code is presented to the victims in a familiar medium, such as their emails or a public poster on display, and conveys a sense of urgency to the victim. 

3. Play: Once a user scans a malicious QR code, they will be redirected to the embedded URL automatically. On this site, they may be prompted to log in and provide their credentials or personal information into a spoofed website that mirrors the original service, or a malicious malware payload is unknowingly downloaded into the users' devices. 

4. Exit: Once the threat actor has carried out their attack successfully, the victim may be redirected to a legitimate website to avoid suspicion further. In the event of a successful attack, the threat actor will now have access to sensitive data, login sessions or internal systems of organisations. Some threat actors may have noted down keystrokes of the users by loading malicious payload as well. Through this, the attacker leaves no visible trace and the QR code remains in place to keep tricking more victims in the future.

As QR codes are visual, they require human interaction to be exploited and thus evade automated system checks as spam or harmful content. Moreover, attackers also conceal their tracks and ensure users are more likely to click on the URL hidden in the malicious QR codes by shortening their URLs or deploying dynamic QR codes that change over time, which further increases the difficulty to trace these attacks back to them.  

Diamond Model:
![QRishing Diamond Model](/assets/img/QRishing/DiamondModel.png)
*Figure 1- Diamond Model Framework*

- Adversary: Threat actors using social engineering to harvest credentials or deliver malware. 
- Infrastructure: Fake domains or malicious URLs behind QR code
- Victim: Victims tricked into scanning the QR code
- Capability: Credential stealing, Device compromise, Session hijacking, Persistence, Evasion tactics.


# Indicators of Compromise
1. Technical IOCs
- Suspicious URLs embedded in QR codes
- Obfuscated or shortened URLs 
- Domains misspelled slightly 
- Non-HTTPS links
- URLs containing IP Addresses 
- Unusual top-level domains (e.g. .tk, .gq, .xyz)
- Redirection chains to phishing page from benign site
- DNS Indicators
    - Newly registered domains
    - Known phishing domains

2. Behavioral IOCs
- Unexpected login prompts or spoofed login portals
- Auto-launch of payment or wallet apps
- Malicious file downloads
    - .apk, .exe, or .docm file force downloaded

3. Visual IOCs
- Tampered signage placed over real QR codes
- Emails or PDFs with QR codes

# Threat Analysis
We now map the QRishing attack to the STRIDE framework, which is a model that categorises threat types into one of six different categories: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege. We categorise the threat types associated with the WannaCry attack as follows:  
- Spoofing: The attacker fakes the identity of a legitimate website being redirected by the QR code to obtain sensitive information from the user and gain unauthorized access into the system. 
- Repudiation: QR codes leave minimal traceability, as an attack brought about by a QR code can almost never be digitally traced back to the threat actor via the QR code. Typically, for an attack to be initiated, the user is required to scan the QR code and unknowingly click on the malicious URL. As such, no clear log ties the threat actor to the malicious activity directly.
- Elevation of Privilege: The threat actor may trick users into downloading malicious applications that may request excessive unnecessary permissions. This will allow the threat actors to escalate access within their system.

To visualise this, we score the extent to which each component in STRIDE played a part in the threat types imposed by the QRishing attack, on a scale of 1 - 5. For a statistical representation of the scoring of each STRIDE component, we arrive at the following diagram: 

![QRishing STRIDE Radar](/assets/img/QRishing/QRishing%20Radar.png)
*Figure 2- STRIDE Framework Radar Chart*

# Impacts and Consequences
QRishing attacks may bring about devastating consequences, contributing to financial loss and disruption to business services through a security breach. When a user scans a malicious QR code, they may allow attackers to gain unauthorized access to personal or corporate data, or the system architecture, leading to direct financial theft, fraudulent transactions or disruptions to business procedures. The use of malicious QR codes by threat actors particularly affect the confidentiality and integrity of the organization data and systems.

- Confidentiality: The confidentiality of data is breached as sensitive credentials and personal information are harvested, often without the user’s awareness.
- Integrity: The integrity of systems and data is jeopardized when malware is introduced or when unauthorized changes are made to critical information.
- Availability: Allowing threat actors access to the system architecture may open doors for subsequent exploitation, leading to denial-of-service conditions or operational downtime. 

As QR codes become more integrated into everyday transactions and public communications, the potential for large-scale exploitation through QRishing increases—making user education, secure scanning practices, and threat detection mechanisms essential in mitigating these risks.

# Defense and Mitigation
- Avoid scanning random QR codes: Do not scan random QR codes unless they're from a trusted sites or known sources.
- Use QR code scanners that display URLs: Use a QR code scanner that can display the URL tagged to the QR code before redirecting the user to the corresponding website. This is to be able to verify the legitimacy of the URL link before clicking on it.
- Check the source: If possible, observe the URL tagged to the QR code for any discrepancies (typos, extra characters, etc) compared to the original URL from popular and well-known sites.
- Keep security updates to date: Ensure that security updates are kept up to date such that if a device was infected with a malicious payload through phishing, it can be blocked from causing any harm by the patch updates. 

# Ctrl + Alt + Theories
One potential way to prevent the tampering of existing QR codes is to research into generating QR code scanners with built in antivirus filters, such that once a QR code is scanned, the URL is scanned by the antivirus filter. If the software detects a potentially malicious URL, it flags it and prevents the user from being redirected to the URL website immediately.

QR codes are used by smart devices to recognize and link to different apps for communication as well, which leaves vulnerable spots for threat actors to exploit as well. Thus, to protect the IoT systems before threat actors begin to poison QR codes used as communication by them, methods such as appropriate checking must be used within these systems before the QR code is scanned and trusted as well. 


# Final Words 
As the digital landscape progresses to greater heights, it becomes glaringly obvious that convenience often comes at the expense of caution. While QR codes were designed to be as simple tools to facilitate efficient communication and seamless access to resources, it has now opened easily exploitable potential attack vectors via the introduction of QRishing techniques. This attack form highlights the adaptability of social engineering techniques. While traditional phishing remains prevalent, QRishing capitalizes on newer habits introduced to the public, compromising our increasing digitization of daily interactions, our trust in new technology, and our tendency to scan without scrutiny. 

As threat actors continue to exploit the intersection between human behavior and digital interfaces, proactive vigilance is an essential shield to develop. For in cybersecurity, even the smallest actions, like a single scan, could lead to significant consequences. 

# References
https://emailsecurity.checkpoint.com/blog/the-dark-side-of-qr-codes-business-impact-of-quishing
https://cds.thalesgroup.com/en/hot-topics/beware-square-discover-risks-qr-code-phishing
