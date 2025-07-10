---
title: "WannaCry: When Negligence Opened The Door"
date: 2025-05-04
categories: ["Case Studies"] 
tags: ["WannaCry", "Ransomware", "SMB Vulnerability", "Malware", "2017", "Lazarus Group"]
toc: true
comments: true
---

# At a Glance
The most devastating attacks are often the ones no one anticipates at all, or the ones that slip past the smallest opening unnoticed until it’s too late. One such attack hit organisations in almost every industry across the world in May 2017. Hospital monitors went dark, ATM screens froze, and one message blinked back at a stunned world in daring red letters: ‘Ooops, your files have been encrypted!’ 

Occurring on 12th May 2017, the WannaCry ransomware attack, known as one of the most infamous cyberattacks in history, impacted several well-known organisations all over the world. WannaCry was a ruthless crypto-ransomware targeting computers running on Microsoft Windows as their operating system. When a device was affected, valuable files and data were encrypted and taken hostage with a grim ultimatum – pay a ransom in Bitcoin, or lose everything. The attack spread like wildfire, affecting more than 200000 computers in over 150 countries, including giants like FedEx, Nissan, Honda and even vital services such as the UK National Health Service. The widespread reliance on Microsoft Windows systems by devices worldwide amplified the damage, leaving countless organisations operationally paralysed by the malware. In addition to exposing technical vulnerabilities, WannaCry served as a brutal reminder of the storm of chaos that can be brought upon by even the smallest oversight.
But chaos is never a tangle of indecipherable runes. More often than not, it’s usually a methodical – sometimes even predictable – puzzle that can be broken down into steps. In this post, we’ll map the WannaCry ransomware attack across the MITRE ATT&CK Framework to piece the puzzle— from how initial access was gained, to the tactics used for persistence, execution, and impact – and learn how to recognize the signs before history repeats itself.

# Threat Actor Analysis
#### **Name:** Lazarus Group
#### **Suspected Origin:** North Korea
#### **Alleged Backing:** There are several theories stating that the WannaCry attack carried out by the Lazarus Group was backed by the government of North Korea, while others suggest that the attack may be from a completely different region and contain obvious authorship clues to tie it to North Korea. However, without evidence, these theories remain as that.
#### **Known Motivations:**
- **Financial Gain:** Ransomware is a type of cybercrime. Since files and data were encrypted and victims were asked to pay a ransom amount, the attackers were likely looking to make money off the attack by making data unavailable to victims.
- **Cyber Espionage:** In a world of hybrid threats, WannaCry might have been less about the ransom and more about the reach. If it had been proven to be state-sponsored, it would redefine ransomware not just as a weapon of crime but as a tool of espionage, chaos, and coercion.

# The Attack: An Anatomy 
The WannaCry malware mainly exploited systems using Microsoft Windows that were in need of an update soon. The malware was not particularly stealthy-- it barged through the front door of systems via a vulnerability in the Microsoft Server Message Block 1.0 (SMBv1) protocol. With the use of specially crafted packets known as EternalBlue, the SMB vulnerability could be tricked into executing arbitrary code in affected systems. The EternalBlue packets, developed by the United States National Security Agency, were effective only in systems that ran on older versions of Microsoft Windows.  

![WannaCry Timeline](/assets/img/WannaCry/Timeline.png)
*Figure 1: Timeline of events*

Here, the timeline pieces everything together. The United States National Security Agency had previous knowledge of the EternalBlue vulnerability, but had not disclosed it to Microsoft or the public for several years. However, this information was stolen and leaked by a group that called themselves 'The Shadow Brokers'. In response, in early 2017 at around March, Microsoft Windows had sent out a security patch, MS17-010, to address the vulnerability. However, several devices remained unpatched, leaving the vulnerability exposed and inviting. In May 2017, the infamous WannaCry attack was then believed to have been launched by the North Korean cybercriminal group 'The Lazarus Group', affecting several devices and business operations globally. 

![WannaCry Timeline](/assets/img/WannaCry/wannacry_screen.png)
*Figure 2: WannaCry ransom note screenshot*

The WannaCry ransomware spread as a worm, self-propagating rapidly across every other device that communicated with a compromised device. The ransomware, when having successfully infected a device, appeared as a self-contained program containing several files, including:
- Application used to encrypt and decrypt data
- Files with respective encryption keys
- A copy of Tor (Command and Control (C2) operations, allowing infected devices to connect anonymously to the attacker's infrastructure)

Once infected, the WannaCry malware encrypted files on the compromised device or server, making the data unavailable to users until a ransom of $300 (later increased to $600 if the first time limit given was exceeded) in bitcoin was paid within a stipulated period of time. A compromised device could not be used to access any other screen at all, and only displayed a singular static screen (Figure 2), most notably containing a countdown to the end of the given timeframe within which the ransom was to be paid. WannaCry was unique in the sense that it combined a self-propagating worm with ransomware. 

A few hours after the attack, a security blogger discovered a security stall to stall the attack by reverse engineering the source code, which led him to find that the malware queried a nonexistent domain before each execution. He then registered the domain, which caused the WannaCry copies being spread to stop executing once it received a response from the domain. 

##MITRE ATT&CK FRAMEWORK: Tactics, Techniques & Procedures

![WannaCry MITRE Table](/assets/img/WannaCry/WannaCry_MITRE.png)
*Figure 3: MITRE ATT&CK - WannaCry*
---
<style>
  table {
    border-collapse: collapse;
    width: 100%;
  }

  th, td {
    border: 1px solid #999;
    padding: 6px;
    text-align: left;
  }

  thead {
    background-color: #ddd;
  }

  .row-group-1,
  .row-group-3,
  .row-group-6 {
    background-color: #f9f9f9;
  }

  .row-group-2,
  .row-group-4,
  .row-group-5,
  .row-group-7,
  .row-group-8 {
    background-color: #ffffff;
  }
</style>

<table>
  <thead>
    <tr>
      <th>Order</th>
      <th>Tactic</th>
      <th>TTP</th>
      <th>Description</th>
    </tr>
  </thead>
  <tbody>
    <tr class="row-group-1">
      <td>1</td>
      <td>Execution</td>
      <td>T1047 - Windows Management Instrumentation</td>
      <td><strong>WannaCry</strong> utilises wmic to delete shadow copies.</td>
    </tr>
    <tr class="row-group-2">
      <td>2</td>
      <td>Persistence</td>
      <td>T1543 - Create or Modify System Processes: Windows Service</td>
      <td><strong>WannaCry</strong> creates the service "mssecsvc2.0" with the display name "Microsoft Security Center (2.0) Service."</td>
    </tr>
    <tr class="row-group-3">
      <td>3</td>
      <td>Privilege Escalation</td>
      <td>T1543 - Create or Modify System Processes: Windows Service</td>
      <td><strong>WannaCry</strong> creates the service "mssecsvc2.0" with the display name "Microsoft Security Center (2.0) Service."</td>
    </tr>
    <tr class="row-group-4">
      <td rowspan="2">4</td>
      <td>Defence Evasion</td>
      <td>T1222 - File and Directory Permissions Modification: Windows File and Directory Permissions Modification</td>
      <td><strong>WannaCry</strong> uses <code>attrib +h</code> and <code>icacls /grant Everyone:F /T /C /Q</code> to make some of its files hidden and grant all users full access controls.</td>
    </tr>
    <tr class="row-group-4">
      <td></td>
      <td>T1564 - Hide Artifacts: Hidden Files and Directories</td>
      <td><strong>WannaCry</strong> uses <code>attrib +h</code> to make some of its files hidden.</td>
    </tr>
    <tr class="row-group-5">
      <td rowspan="4">5</td>
      <td>Discovery</td>
      <td>T1083 - File and Directory Discovery</td>
      <td><strong>WannaCry</strong> searches for a variety of user files by file extension before encrypting them using RSA and AES, including Office, PDF, image, audio, video, source code, archive/compression format, and key and certificate files.</td>
    </tr>
    <tr class="row-group-5">
      <td></td>
      <td>T1120 - Peripheral Device Discovery</td>
      <td><strong>WannaCry</strong> contains a thread that will attempt to scan for new attached drives every few seconds. If one is identified, it will encrypt the files on the attached device.</td>
    </tr>
    <tr class="row-group-5">
      <td></td>
      <td>T1018 - Remote System Discovery</td>
      <td><strong>WannaCry</strong> scans its local network segment for remote systems to try to exploit and copy itself to.</td>
    </tr>
    <tr class="row-group-5">
      <td></td>
      <td>T1016 - System Network Configuration Discovery</td>
      <td><strong>WannaCry</strong> will attempt to determine the local network segment it is a part of.</td>
    </tr>
    <tr class="row-group-6">
      <td>6</td>
      <td>Lateral Movement</td>
      <td>T0866 - Exploitation of Remote Services</td>
      <td><strong>WannaCry</strong> initially infected IT networks, but by means of an exploit (particularly the SMBv1-targeting MS17-010 vulnerability) spread to industrial networks.</td>
    </tr>
    <tr class="row-group-7">
      <td rowspan="2">7</td>
      <td>Command and Control</td>
      <td>T1573 - Encrypted Channel: Asymmetric Cryptography</td>
      <td><strong>WannaCry</strong> uses Tor for command and control traffic and routes a custom cryptographic protocol over the Tor circuit.</td>
    </tr>
    <tr class="row-group-7">
      <td></td>
      <td>T1090 - Proxy: Multi-hop Proxy</td>
      <td><strong>WannaCry</strong> uses Tor for command and control traffic.</td>
    </tr>
    <tr class="row-group-8">
      <td rowspan="3">8</td>
      <td>Impact</td>
      <td>T1486 - Data Encrypted for Impact</td>
      <td><strong>WannaCry</strong> encrypts user files and demands that a ransom be paid in Bitcoin to decrypt those files.</td>
    </tr>
    <tr class="row-group-8">
      <td></td>
      <td>T1490 - Inhibit System Recovery</td>
      <td><strong>WannaCry</strong> uses <code>vssadmin</code>, <code>wbdadmin</code>, <code>bcedit</code>, and wmic to delete and disable operating system recovery features.</td>
    </tr>
    <tr class="row-group-8">
      <td></td>
      <td>T1489 - Service Stop</td>
      <td><strong>WannaCry</strong> attempts to kill processes associated with Exchange, Microsoft SQL Server, and MySQL to make it possible to encrypt their data stores.</td>
    </tr>
  </tbody>
</table>


# Threat Landscape & Modelling
We now map the WannaCry ransomware attack to the STRIDE framework, which is a model that categorises threat types into one of five different categories: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege. We categorise the threat types associated with the WannaCry attack as follows: 
- **Tampering with Data:** Data was encrypted and withheld from organisations until a ransom was paid.
- **Denial of Service:** The WannaCry ransomware froze systems with a static screen, preventing affected users any access to their systems and halting operations. Thus, it effectively acted as a Denial of Service event.
- **Elevation of Privilege:** The WannaCry ransomware took advantage of the EternalBlue vulnerability (CVE-2017-0144) in Microsoft’s SMB protocol to gain unauthorised access and higher-level privileges within infected systems.

To visualise this, we score the extent to which each component in STRIDE played a part in the threat types imposed by the WannaCry ransomware, on a scale of 1 - 5. For a statistical representation of the scoring of each STRIDE component, we arrive at the following diagram: 

![WannaCry STRIDE Radar](/assets/img/WannaCry/WannaCry_Radar.png)
*STRIDE Framework: Radar Chart*

# Indicators of Compromise
## IPs or domains (for C2)
- IPv4   	197(.)231.221.211
- IPv4   	128(.)31.0.39
- IPv4   	149(.)202.160.69
- IPv4   	46(.)101.166.19
- IPv4   	91(.)121.65.179


## URLs
- hxxp://www(.)btcfrog(.)com/qr/bitcoinpng(.)php?address
- hxxp://www(.)rentasyventas(.)com/incluir/rk/imagenes(.)html
- hxxp://www(.)rentasyventas(.)com/incluir/rk/imagenes(.)html?retencion=081525418
- hxxp://gx7ekbenv2riucmf(.)onion
- hxxp://57g7spgrzlojinas(.)onion
- hxxp://xxlvbrloxvriy2c5(.)onion
- hxxp://76jdd2ir2embyv47(.)onion
- hxxp://cwwnhwhlz52maqm7(.)onion
- hxxp://197.231.221(.)211       	Port:9001
- hxxp://128.31.0(.)39                	Port:9191
- hxxp://149.202.160(.)69         	Port:9001
- hxxp://46.101.166(.)19           	Port:9090
- hxxp://91.121.65(.)179           	Port:9001


## File hashes:
- ### SHA256:
    - 7E369022DA51937781B3EFE6C57F824F05CF43CBD66B4A24367A19488D2939E4
    - 9B60C622546DC45CCA64DF935B71C26DCF4886D6FA811944DBC4E23DB9335640
    - 4A468603FDCB7A2EB5770705898CF9EF37AADE532A7964642ECD705A74794B79
    - 09A46B3E1BE080745A6D8D88D6B5BD351B1C7586AE0DC94D0C238EE36421CAFA
    - 4186675CB6706F9D51167FB0F14CD3F8FCFB0065093F62B10A15F7D9A6C8D982
    - 5AD4EFD90DCDE01D26CC6F32F7CE3CE0B4D4951D4B94A19AA097341AFF2ACAEC
    - 00FDB4C1C49AEF198F37B8061EB585B8F9A4D5E6C62251441831FE2F6A0A25B7
    - B9C5D4339809E0AD9A00D4D3DD26FDF44A32819A54ABF846BB9B560D81391C25
    - 2584E1521065E45EC3C17767C065429038FC6291C091097EA8B22C8A502C41DD
    - 2CA2D550E603D74DEDDA03156023135B38DA3630CB014E3D00B1263358C5F00D
    - ED01EBFBC9EB5BBEA545AF4D01BF5F1071661840480439C6E5BABE8E080E41AA
    - C365DDAA345CFCAFF3D629505572A484CFF5221933D68E4A52130B8BB7BADAF9
    - 201F42080E1C989774D05D5B127A8CD4B4781F1956B78DF7C01112436C89B2C9
    - CA29DE1DC8817868C93E54B09F557FE14E40083C0955294DF5BD91F52BA469C8
    - 7108D6793A003695EE8107401CFB17AF305FA82FF6C16B7A5DB45F15E5C9E12D
    - 7C465EA7BCCCF4F94147ADD808F24629644BE11C0BA4823F16E8C19E0090F0FF
    - 24D004A104D4D54034DBCFFC2A4B19A11F39008A575AA614EA04703480B1022C
    - 4B76E54DE0243274F97430B26624C44694FBDE3289ED81A160E0754AB9F56F32
    - F8812F1DEB8001F3B7672B6FC85640ECB123BC2304B563728E6235CCBE782D85
    - DFF26A9A44BAA3CE109B8DF41AE0A301D9E4A28AD7BD7721BBB7CCD137BFD696
    - AEE20F9188A5C3954623583C6B0E6623EC90D5CD3FDEC4E1001646E27664002C
    - 2372862AFAA8E8720BC46F93CB27A9B12646A7CBC952CC732B8F5DF7AEBB2450 
    - 43D1EF55C9D33472A5532DE5BBE814FEFA5205297653201C30FDC91B8F21A0ED 
    - 49FA2E0131340DA29C564D25779C0CAFB550DA549FAE65880A6B22D45EA2067F 
    - 616E60F031B6E7C4F99C216D120E8B38763B3FAFD9AC4387ED0533B15DF23420 
    - 49FA2E0131340DA29C564D25779C0CAFB550DA549FAE65880A6B22D45EA2067F 
    - 616E60F031B6E7C4F99C216D120E8B38763B3FAFD9AC4387ED0533B15DF23420 
    - 24D004A104D4D54034DBCFFC2A4B19A11F39008A575AA614EA04703480B1022C
    - 043E0D0D8B8CDA56851F5B853F244F677BD1FD50F869075EF7BA1110771F70C2
    - 5D26835BE2CF4F08F2BEEFF301C06D05035D0A9EC3AFACC71DFF22813595C0B9
    - 76A3666CE9119295104BB69EE7AF3F2845D23F40BA48ACE7987F79B06312BBDF
    - BE22645C61949AD6A077373A7D6CD85E3FAE44315632F161ADC4C99D5A8E6844
    - F7C7B5E4B051EA5BD0017803F40AF13BED224C4B0FD60B890B6784DF5BD63494
    - FC626FE1E0F4D77B34851A8C60CDD11172472DA3B9325BFE288AC8342F6C710A
    - 09A46B3E1BE080745A6D8D88D6B5BD351B1C7586AE0DC94D0C238EE36421CAFA
    - AEE20F9188A5C3954623583C6B0E6623EC90D5CD3FDEC4E1001646E27664002C
    - C365DDAA345CFCAFF3D629505572A484CFF5221933D68E4A52130B8BB7BADAF9


- ### SHA1
    - 5D68E2779E2CCCEE49188363BE6CDDBB0BAC7053
    - 14249E7FB3FB6F4B363C47D5AAE9F46DAB2083C1
    - 47A9AD4125B6BD7C55E4E7DA251E23F089407B8F
    - 87420A2791D18DAD3F18BE436045280A4CC16FC4
    - 50049556B3406E07347411767D6D01A704B6FEE6
    - AF7DB69CBAA6AB3E4730AF8763AE4BF7B7C0C9B2
    - 8286354A6A051704DEC39993AF4E127D317F6974
    - 45356A9DD616ED7161A3B9192E2F318D0AB5AD10
    - BD44D0AB543BF814D93B719C24E90D8DD7111234
    - BE5D6279874DA315E3080B06083757AAD9B32C23
    - 5FF465AFAABCBF0150D1A3AB2C2E74F3A4426467
    - 8897C658C0373BE54EEAC23BBD4264687A141AE1
    - 1BC604573CEAB106E5A0E9C419ADE38739228707
    - A52E025D579BEBAE7C64CB40236B469B3C376024
    - B8B49A36A52ABCF537FEBCBF2D09497BEE79987D
    - A1818054B40EC9E28BEBE518ECC92F4ECEAFFEF4
    - E889544AFF85FFAF8B0D0DA705105DEE7C97FE26
    - F3839C1CDE9CE18021194573FDF0CAE09A62172F
    - 51E4307093F8CA8854359C0AC882DDCA427A813C
    - FB18818FC383330B401FC5B332CC63A5BBD4CD30
    - B629F072C9241FD2451F1CBCA2290197E72A8F5E
    - E889544AFF85FFAF8B0D0DA705105DEE7C97FE26
    - BC978DB3D2DC20B1A305D294A504BB0CEB83F95A
    - 02408BB6DC1F3605A7D3F9BAD687A858EC147896
    - 4FDAE49BE25846CA53B5936A731CE79C673A8E1F
    - 120ED9279D85CBFA56E5B7779FFA7162074F7A29
    - 432C1A5353BAB4DBA67EA620EA6C1A3095C5D4FA
    - 64B8E679727E99A369A2BE3ED800F7B969D43AA8
    - 87420A2791D18DAD3F18BE436045280A4CC16FC4
    - B629F072C9241FD2451F1CBCA2290197E72A8F5E
    - 8897C658C0373BE54EEAC23BBD4264687A141AE1

- ### MD5
    - 3175E4BA26E1E75E52935009A526002C
    - 31DAB68B11824153B4C975399DF0354F
    - 4FEF5E34143E646DBF9907C4374276F5
    - 509C41EC97BB81B0567B059AA2F50FE8
    - 5BEF35496FCBDBE841C82F4D1AB8B7C2
    - 638F9235D038A0A001D5EA7F5C5DC4AE
    - 775A0631FB8229B2AA3D7621427085AD
    - 7BF2B57F2A205768755C07F238FB32CC
    - 7F7CCAA16FB15EB1C7399D422F8363E8
    - 8495400F199AC77853C53B5A3F278F3E
    - 84C82835A5D21BBCF75A61706D8AB549
    - 86721E64FFBD69AA6944B9672BCABB6D
    - 8DD63ADB68EF053E044A5A2F46E0D2CD
    - B0AD5902366F860F85B892867E5B1E87
    - B675498639429B85AF9D70BE1E8A8782
    - D6114BA5F10AD67A4131AB72531F02DA
    - DB349B97C37D22F5EA1D1841E3C89EB4
    - E372D07207B4DA75B3434584CD9F3450
    - F107A717F76F4F910AE9CB4DC5290594
    - F529F4556A5126BBA499C26D67892240
    - 4DA1F312A214C07143ABEEAFB695D904
    - DB349B97C37D22F5EA1D1841E3C89EB4
    - 3BC855BFADFEA71A445080BA72B26C1C
    - B9B3965D1B218C63CD317AC33EDCB942
    - 808182340FB1B0B0B301C998E855A7C8
    - 5C7FB0927DB37372DA25F270708103A2
    - 66DDBD108B0C347550F18BB953E1831D
    - B6DED2B8FE83BE35341936E34AA433E5
    - 509C41EC97BB81B0567B059AA2F50FE8
    - 4DA1F312A214C07143ABEEAFB695D904
    - 86721E64FFBD69AA6944B9672BCABB6D


## Registry changes
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run "[random].exe"
- HKEY_CLASSES_ROOT\CLSID\[ Ransom:Win32.WannaCrypt]
- HKEY_CURRENT_USER\Software\AppDataLow\Software\ Ransom:Win32.WannaCrypt</Content>
- HKEY_CURRENT_USER\Software\ Ransom:Win32.WannaCrypt character</Content>
- HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ Ransom:Win32.WannaCrypt
- HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\BrowserHelperObjects\[random numbers]

## Files
- qeriuwjhrf
- mssecsvc.exe
- cliconfg.exe
- diskpart.exe
- lhdfrgui.exe
- b9c5d4339809e0ad9a00d4d3dd26fdf44a32819a54abf846bb9b560d81391c25
- b9c5.bin
- 2584E1521065E45EC3C17767C065429038FC6291C091097EA8B22C8A502C41DD.dat
- waitfor.exe
- tasksche.exe
- diskpart.exe
- 8dd63adb68ef053e044a5a2f46e0d2cd.virus
- Message
- kbdlv (3.13)
- ransomware07_no_detection.exe
- mssecsvc.exe
- mssecsvc.exe
- taskhcst.eee
- WCry_WannaCry_ransomware.exe
- localfile~
- taskhcst.exe
- findstr
- dvdplay
- Cmd.Exe
- taskhcst.exe1
- diskpart.exe
- WCry_WannaCry_ransomware.exe
- diskpart.exe


# Impacts and Consequences
The highly interconnected nature of the networks contributed to how massive the damage was due to the attack, affecting nearly 300,000 devices across 150 countries and costing a total of $4 billion in losses alone globally. The attack has caused significant financial and reputational damage to businesses in several sectors, including hospitals. 

The WannaCry attack caused hospitals and scheduled surgeries all around the UK to be affected. It was estimated that close to 19,000 patients cancelled their appointments after the attack commenced, and a terrifying number of ambulances were rerouted, which left people in dire need of aid stranded for hours. Hospitals in the UK incurred a loss of almost £92 million.

# Defense and Mitigations
- **Update software patches and operating system updates regularly:** Regularly applying software patches is a critical defence against allowing ransomware such as WannaCry to exploit known vulnerabilities in unpatched systems. Security patches aim to identify and close the vulnerability gaps, preventing attackers from leveraging outdated code to gain access or execute malicious payloads. Timely updates ensure that systems stay resilient against evolving threats and reduce the attack surface significantly. 
- **Install/update internet security software:** Keeping internet security software installed and updated is crucial, as it may help to detect and block ransomware (such as the WannaCry ransomware) before it is able to execute. By using real-time monitoring and behaviour-based analysis, these tools catch suspicious actions such as unauthorised file encryption, patch known vulnerabilities, and block malicious network traffic, cutting off the attack at its roots. 
- **Backup data regularly:** It is important to keep multiple copies of important information in several locations, such that when one is compromised, the data is still available for use. Backing up data to the cloud as well as to a hardware device should be considered, as no business should rely on only one copy of data to continue regular operations.
- **Don’t Pay the Ransom:** If compromised, paying the ransom is strongly discouraged as attackers rarely provide a reliable method to decrypt the compromised files. Their primary goal is financial gain and not data recovery, and many victims report that their files remain inaccessible even after payment. Refusing to pay also helps reduce the profitability of ransomware campaigns, discouraging future attacks.

# Ctrl + Alt + Theories
- The attackers had threatened to delete victims’ files if the ransom wasn’t paid within the stipulated time, but this may have been an empty threat designed purely to increase FUD — fear, uncertainty, and doubt — among victims and pressure them into paying more quickly.
- The ransomware code appeared sloppy and hastily written, likely rushed into deployment right after Microsoft released the security patch, aiming to infect as many outdated systems as possible before they could be updated.
- Even the decryption process was unreliable — several victims reported being unable to recover their files after paying the ransom, suggesting that the attackers' decryption key mechanism was flawed or intentionally dysfunctional.

# Final Words
A security patch can only protect what it reaches, for its power lies not in its availability, but in its action. In the case of WannaCry, systems practically handed attackers access without a fight simply by running on outdated versions. All it took was one unguarded backdoor, left wide open by negligence, for chaos to flood in. Attackers don’t always need a hundred doors – sometimes, just one opening or one missed update will do. The single crack in the armour was all it took for WannaCry to cripple hospitals and corporations alike. Defence is a game of diligence and discipline. For, at the end of the day, the real vulnerability WannaCry exploited wasn’t the code – it was our complacency.

# References
- https://www.cloudflare.com/en-gb/learning/security/ransomware/wannacry-ransomware/
- https://www.kaspersky.com/resource-center/threats/ransomware-wannacry
- https://www.akamai.com/glossary/what-is-wannacry-ransomware
- https://attack.mitre.org/software/S0366/


