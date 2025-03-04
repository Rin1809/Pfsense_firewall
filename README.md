<h1>This repository, no coding. ᓚᘏᗢ </h1>

As a student learning about cyber security, i just want to show what i did and how a firewall work (doing realistic simulation lab ). If care about it so expan it down ᓚᘏᗢ


   
## LAB Document
<details>
   <summary>PfSense Firewall Model 1</summary>
   
# PfSense Firewall Configuration: Realistic Lab Simulation 1

![image](https://github.com/user-attachments/assets/1cbdc6eb-a568-4ec1-b49c-3a5783ab604c)
(Pfsense Firewall Dashboard)

This document outlines a practical lab simulation demonstrating common firewall configuration tasks using pfSense version 2.7.2-RELEASE (amd64). This lab setup involves configuring network zones (WAN, LAN, DMZ, DTB), setting up Network Address Translation (NAT) rules, implementing web access restrictions using Squid, and opening specific ports for different network zones and user groups. This lab provides a hands-on experience with essential firewall administration concepts and techniques using pfSense, a widely used open-source firewall platform.

**Set Up:** The pfSense system is running version 2.7.2-RELEASE (amd64). The network interface configuration includes 4 network cards, each assigned to a specific network zone. This segmented network architecture is a fundamental security practice to isolate different parts of your network and control traffic flow between them. **Why network segmentation?** Segmenting your network into zones significantly enhances security by:

*   **Limiting Breach Scope:** If one zone is compromised, the attacker's access is limited to that zone, preventing easy lateral movement to other sensitive parts of the network.
*   **Granular Access Control:**  Allows you to apply different security policies and firewall rules to each zone based on its specific needs and risk profile.
*   **Improved Monitoring and Logging:**  Segmented networks make it easier to monitor traffic flow within and between zones, aiding in security monitoring and incident detection.

**Network Interface Configuration:**

| Interface | Interface Name | IP Address         | Zone Description                                  |
| --------- | -------------- | ------------------ | --------------------------------------------------- |
| WAN       | em0            | 192.168.19.10/24   | **Wide Area Network:** Represents the public internet connection.  This interface connects pfSense to the external network, simulating the internet. |
| LAN       | em1            | 192.168.20.10/24   | **Local Area Network:**  Simulates the internal corporate network for employees.  This zone represents the trusted internal network where regular employee workstations and internal resources reside. |
| DMZ       | em2 (opt1)     | 192.168.30.10/24   | **Demilitarized Zone:**  Hosts publicly accessible servers like web servers, isolated from the internal LAN. The DMZ acts as a buffer zone between the untrusted internet and the trusted LAN, protecting internal resources. |
| DTB       | em3 (OTP2)     | 192.168.40.10/24   | **Database Zone:**  Dedicated zone for database servers, further isolating sensitive data.  The Database Zone provides an extra layer of security for critical database servers, further segmenting them from the DMZ and LAN. |

**Report Diagram:** (Diagram image showing network zones and pfSense firewall)

![image](https://github.com/user-attachments/assets/e3278967-a581-4181-baa3-eb58b60c9070)

This diagram illustrates a typical three-legged firewall configuration, expanded to four zones for enhanced security. Traffic between these zones will be controlled by firewall rules configured in pfSense.  The pfSense firewall acts as the central point of control, enforcing security policies and managing traffic flow between the different network zones.

---

## 1. Public Web Server Access from DMZ

**Objective:**  To make a web server located in the DMZ (Demilitarized Zone) publicly accessible from the internet. This scenario demonstrates how to use pfSense to publish internal services securely to the internet, a common requirement for organizations hosting web applications. **Why is publishing a web server from the DMZ important?** Organizations often need to provide public access to web applications and services while protecting their internal network. The DMZ provides a secure location for these public-facing servers:

*   **Security Isolation:**  Servers in the DMZ are isolated from the internal LAN. If a DMZ server is compromised, the attacker's access to the internal LAN is significantly limited.
*   **Controlled Access:**  Firewall rules and NAT rules allow you to precisely control what traffic is allowed to reach the DMZ servers and from where.
*   **Public Service Provision:** Enables organizations to host public-facing services like websites, email servers, and application servers in a secure and controlled manner.

**Web Server in DMZ:** We are using an existing web server running on Metasploitable 2, a deliberately vulnerable virtual machine, for demonstration purposes. This Metasploitable 2 server is located in the DMZ network zone with the IP address:

![image](https://github.com/user-attachments/assets/c42c9957-d3ed-4665-bedf-717e3822a6f3)

**Goal:**  Users from the internet should be able to access this web server by accessing the pfSense firewall's public WAN IP address.  This is achieved through port forwarding, a type of Network Address Translation (NAT). **What is NAT Port Forwarding?** NAT Port Forwarding allows external traffic arriving at a specific port on the firewall's public IP address to be redirected to a specific internal server and port. This is essential for making internal services accessible from the internet while using private IP addresses internally.

![image](https://github.com/user-attachments/assets/8e19af50-42ea-4c95-96ec-6b5e501ca28c)

**1.1. Configure NAT Port Forwarding Rule**

**Navigation:** Navigate to **Firewall -> NAT -> Port Forward**. This section in pfSense allows you to create rules for port forwarding, enabling external access to internal services.

**Adding a New Rule:** Click **"+ Add"** to create a new port forwarding rule.

**Rule Configuration:** We will create a rule to forward incoming web traffic (port 80 - HTTP) on the WAN interface to the web server (Metasploitable 2) in the DMZ (192.168.30.20).

![image](https://github.com/user-attachments/assets/d5e1a10e-bd74-4b13-995e-febcbb2f9c93)

**Rule Settings Explanation:**

*   **A: Protocol TCP/UDP:** Set to **TCP** because HTTP web traffic primarily uses the TCP protocol. While HTTP/3 uses UDP, for this basic setup, TCP is sufficient and more common for standard web servers.
    *   **Rationale:**  Specifying the correct protocol ensures that only traffic using the intended protocol (TCP in this case) is forwarded, enhancing security by filtering out unexpected traffic types.  This prevents attackers from trying to exploit the port forwarding rule with different protocols.
*   **B: Destination port range - HTTP (port 80):**  Set to **HTTP** which defaults to port 80. This defines the port that will be open on the WAN interface of the pfSense firewall to receive incoming web requests.
    *   **Rationale:**  Port 80 is the standard port for HTTP web traffic. By specifying port 80, we are making the web server accessible via the standard web port from the internet.  Users accessing the WAN IP on port 80 will be directed to the web server. You could change this to HTTPS (port 443) if the web server was configured for secure HTTPS traffic, which is highly recommended for production environments.
*   **C: Redirect target -  Metasploitable 2 IP (192.168.30.20):** Set the **Redirect target IP** to `192.168.30.20`, which is the IP address of the Metasploitable 2 web server in the DMZ zone.
    *   **Rationale:**  The Redirect target IP specifies the internal server that will handle the forwarded traffic. In this case, all traffic arriving at the pfSense WAN IP on port 80 will be redirected to the Metasploitable 2 web server at `192.168.30.20` on the same port 80 (by default, the Redirect target port will be the same as the destination port range unless specified otherwise). This effectively maps the public-facing port 80 on the WAN IP to the internal web server.

![image](https://github.com/user-attachments/assets/dc7f23de-3956-4abf-91fd-efa72665e97f)

**Saving and Testing:** Click **Save** to apply the NAT rule. To test, use a machine connected to the internet (simulating an external user) and access the WAN IP address of the pfSense firewall in a web browser.

**Finding WAN IP Address:** Note down the WAN IP address of the pfSense firewall. This IP address is used to access the published web server from the internet.  You can find the WAN IP address in the pfSense dashboard or interface overview. **Why do we need the WAN IP address?** The WAN IP address is the public-facing IP address of the firewall. External users will connect to this IP address, and the firewall will then forward the traffic to the internal web server based on the NAT rule.

![image](https://github.com/user-attachments/assets/67b278b3-0ac5-44fa-bc66-900ab62accf8)

**Test Result:** Accessing the pfSense WAN IP address from an external machine should now successfully display the webpage hosted on the Metasploitable 2 web server in the DMZ. This confirms that the NAT port forwarding rule is working correctly, and the web server is publicly accessible through the firewall. **What does a successful test indicate?** A successful test demonstrates:

*   **NAT Rule Functionality:** The port forwarding rule is correctly configured and is redirecting traffic as intended.
*   **Web Server Accessibility:** The web server in the DMZ is now reachable from the internet through the pfSense firewall.
*   **Basic Public Service Publication:**  You have successfully published an internal service (the web server) to the public internet in a controlled manner using pfSense.

---

## 2. Restricting Web Access for Departments in the LAN Zone

**Objective:** To demonstrate content filtering and web access control for different departments within the LAN zone. This scenario simulates a common corporate requirement to restrict internet access based on departmental needs and security policies. We will use Squid, a proxy server package available in pfSense, to achieve this. **Why content filtering in a corporate environment?** Content filtering is crucial for:

*   **Productivity Enhancement:**  Restricting access to non-work-related websites can improve employee productivity by reducing distractions.
*   **Security Enhancement:** Blocking access to malicious websites, phishing sites, and websites hosting malware reduces the risk of malware infections and security breaches.
*   **Compliance and Policy Enforcement:**  Content filtering helps enforce company policies regarding internet usage and can aid in meeting regulatory compliance requirements.
*   **Bandwidth Management:**  Limiting access to bandwidth-intensive websites like streaming services can conserve network bandwidth.

**Department Breakdown and Access Requirements:**

| Department        | Allowed Website(s) | IP Range         | Access Policy                                  |
| ----------------- | ------------------ | ------------------ | ---------------------------------------------- |
| Human Resources (Nhan Su) | yurineko.net      | 192.168.20.20-30   | Only access to yurineko.net                      |
| Technical (Ky Thuat)     | w3schools.com     | 192.168.20.40-50   | Only access to w3schools.com                     |
| Project (Du An)      | truyenonl.com     | 192.168.20.60-70   | Only access to truyenonl.com                    |
| Admin             | Full Access        | 192.168.20.50   | Unrestricted internet access                     |

**2.1. Setup Squid Rule for Human Resources Department**

**Navigation:** Navigate to **Services -> Squid Proxy Filter -> Target Categories**. This section in pfSense Squid allows you to define categories of websites or specific domains for filtering rules.

**Adding Target Category:**  Click **"+ Add"** to create a new target category.

**Category Configuration:** We will create a category for the allowed website for Human Resources: `yurineko.net`.

![image](https://github.com/user-attachments/assets/4f63b2f0-e580-43dd-99ea-c5f436f8e151)

**Category Settings Explanation:**

*   **"Target Categories" Section:**  In this section, you define the website or domain that will be part of this category.  Here, we input `yurineko.net`. **Why create a "Target Category"?** Target Categories allow you to group websites or domains together, making it easier to manage filtering rules for multiple websites with similar access policies.
*   **(Adding IP address):**  While not strictly necessary for domain-based filtering, the image also shows adding the IP address of `yurineko.net`. This can provide a fallback or ensure filtering even if DNS resolution is bypassed or incorrect. **Why add the IP address in addition to the domain?** Adding the IP address provides an extra layer of filtering. Even if a user bypasses DNS or uses a direct IP address to access `yurineko.net`, the Squid proxy can still match the IP address and apply the filtering rule.

**Navigation:** Navigate to **Services -> Squid Proxy Filter ->  Access Control -> Groups ACLs**. This section allows you to create Access Control Lists (ACLs) based on user groups, IP ranges, and target categories.

**Adding Group ACL:** Click **"+ Add"** to create a new Group ACL for the Human Resources department.

**Group ACL Configuration:** Configure the ACL to allow only the Human Resources department IP range to access the `yurineko.net` category and deny access to all other websites.

![image](https://github.com/user-attachments/assets/9626bb63-a10d-4084-9d5d-b847c6c1fe21)

**Group ACL Settings Explanation:**

*   **"Groups ACL" Section:**  Here, we define the access control rules.  **What is a Group ACL?** A Group Access Control List (ACL) defines access rules based on groups of users or, in this case, groups of IP addresses representing departments.  It allows you to apply different filtering policies to different groups.
*   **"Target Categories":** Select the category you created earlier, `yurineko.net`. This links the ACL to the specific website category.  **Why link to the "Target Category"?** This connects the access control rule to the specific website category you defined. Now, this ACL will control access to websites within the `yurineko.net` category.
*   **"Groups ACL":**  Set the action for this ACL to **"Allow"**. This means that clients matching the "Groups ACL" criteria will be *allowed* to access websites in the "Target Categories". For all other traffic not matching this rule, the default Squid behavior (which can be set to Deny) will apply. **Why set the action to "Allow"?** This rule specifically *allows* access to `yurineko.net` for the Human Resources department. For all other websites, access will be implicitly denied because no "Allow" rule is created for them, and Squid's default behavior is typically to deny access if no explicit rule matches.
*   **"Groups ACL" Section - IP Range:** In the "Groups ACL" section, we will further refine this rule by specifying the IP range for the Human Resources department in a later step using an Alias. We will use an Alias to define the IP range, making the ACL rule more readable and manageable.

**2.2. Create Alias for Human Resources Department IP Range**

**Navigation:** Navigate to **Firewall -> Aliases**. Aliases in pfSense allow you to create named groups of IPs, networks, ports, etc., making firewall rules easier to manage and read. **Why use Aliases?** Aliases are a powerful feature in pfSense for:

*   **Rule Simplification:**  Aliases make firewall and proxy rules more readable and easier to understand by using descriptive names instead of raw IP addresses or port numbers.
*   **Centralized Management:**  Aliases allow you to manage groups of IPs, networks, or ports in one place. If you need to change an IP range or add a port, you only need to modify the Alias, and all rules using that Alias will automatically update.
*   **Reduced Errors:** Using Aliases reduces the chance of errors when creating and managing complex rules, as you are working with named objects instead of manually typing IP addresses or port numbers repeatedly.

**Adding Alias:** Click **"+ Add"** to create a new Alias.

**Alias Configuration:** Create an Alias named "nhansu" (Human Resources) to contain the IP range `192.168.20.20-192.168.20.30`.

![image](https://github.com/user-attachments/assets/f217719e-ce63-4500-b119-acac7ef2f9c7)
![image](https://github.com/user-attachments/assets/81b471c3-24b1-4314-8c37-405305e2f246)

**Alias Settings Explanation:**

*   **Name:** Set the Alias name to `nhansu` (or any descriptive name).  Choosing a descriptive name like `nhansu` (Human Resources) makes the Alias easily identifiable and improves rule readability.
*   **Type:** Choose **"Network(s)"** as the Alias type, as we are defining an IP range.  Selecting "Network(s)" indicates that this Alias will represent a range of IP addresses or a network subnet.
*   **Network(s):** Enter the IP range `192.168.20.20-192.168.20.30`. This defines the IP address range for the Human Resources department clients.  This range should correspond to the IP addresses assigned to machines in the Human Resources department.

**2.3. Create Firewall Rule to Enforce Squid Proxy Filtering**

**Navigation:** Navigate to **Firewall -> Rules -> LAN**. We will create a firewall rule on the LAN interface to enforce the Squid proxy filtering for the Human Resources department.  **Why create a Firewall Rule for Squid?**  While Squid Proxy Filter handles the content filtering itself, a Firewall Rule is needed to *redirect* web traffic from the LAN clients to the Squid proxy server running on pfSense. Without this rule, LAN clients would not automatically use the Squid proxy.

**Adding Firewall Rule:** Click **"+ Add"** to create a new Firewall Rule.

**Firewall Rule Configuration:** Create a rule that applies to the "nhansu" alias and enforces the Squid proxy for web traffic.

![image](https://github.com/user-attachments/assets/d09b6580-c08a-4b04-badc-5920be933657)

**Firewall Rule Settings Explanation:**

*   **Action:** Set to **"Pass"** as we are creating a rule to *allow* traffic that matches the criteria.  We are allowing traffic that we want to be processed by the Squid proxy.
*   **Interface:** Select **"LAN"** because this rule applies to traffic originating from the LAN zone. This rule will be placed on the LAN interface to intercept traffic as it leaves the LAN zone.
*   **Protocol:** Set to **"TCP"** as web traffic is primarily TCP-based. We are primarily concerned with filtering HTTP and HTTPS traffic, which both use TCP.
*   **Source (Src):** Set **"Source"** to **"Alias"** and select the `nhansu` alias we created. This means this rule will only apply to traffic originating from the IP range defined in the `nhansu` alias.
    *   **Rationale:** By setting the source to the `nhansu` alias, we are specifically targeting the Human Resources department's clients with this rule.  Only traffic from machines in the Human Resources department IP range will be redirected to the Squid proxy.
*   **Destination (Destination):** Set **"Destination"** to **"any"**. This means that the destination can be any IP address or network.  While we are restricting *web access*, the firewall rule itself is broadly applied to any destination. The *actual web access restriction* is handled by the Squid proxy rules we configured earlier.
    *   **Rationale:** The firewall rule itself doesn't directly block websites. Instead, it *redirects* web traffic from the Human Resources department to the Squid proxy. The Squid proxy then applies the content filtering rules based on the "Target Categories" and "Groups ACLs" we configured.  The destination being "any" means *all* outbound TCP traffic from the Human Resources department will be intercepted and sent to the proxy.
*   **Extra Options - "Gateway" and "Schedule" (Not shown in image, but important considerations):**
    *   **Gateway:**  In more complex network setups with multiple gateways, you might need to specify the gateway to use for this rule. In this simple lab, the default gateway is likely sufficient.
    *   **Schedule:** You can optionally schedule this rule to be active only during certain times of the day or days of the week. This can be useful for implementing time-based access policies (e.g., restricting non-work-related website access during working hours).

**Result - Testing Human Resources Department Access:**

![image](https://github.com/user-attachments/assets/92940b17-b142-4110-8b11-cd695843feb0)

**Testing Procedure:**

1.  **Client Machine:** Use a client machine with an IP address within the Human Resources department IP range (e.g., `192.168.20.25`).  This simulates a user workstation within the Human Resources department.
2.  **Proxy Settings:**  Configure the client machine's web browser to use the pfSense LAN IP address (`192.168.20.10`) as its proxy server, and set the proxy port to `3128` (the default Squid proxy port in pfSense).  **Why configure proxy settings?** Configuring the browser to use the pfSense LAN IP as a proxy ensures that all web traffic from this client machine is routed through the Squid proxy running on pfSense.
3.  **Access Allowed Website:** Attempt to access `yurineko.net`. Access should be successful. This verifies that the "Allow" rule for `yurineko.net` in Squid is working for the Human Resources department.
4.  **Access Blocked Website:** Attempt to access `youtube.com`. Access should be blocked by the Squid proxy, displaying an error message.  This verifies that access to websites *not* in the allowed category is being denied by the Squid proxy for the Human Resources department.

![image](https://github.com/user-attachments/assets/cdd3c863-5888-42fd-8f86-884a8e795c6f)

**Similar Configurations for Other Departments:**  Repeat steps 2.1, 2.2, and 2.3 to configure Squid rules and firewall rules for the Technical and Project departments, each with their respective allowed websites and IP ranges as defined in the department breakdown table. This involves creating new Target Categories for `w3schools.com` and `truyenonl.com`, new Aliases for the IP ranges of the Technical and Project departments, and new Group ACLs and Firewall Rules similar to those created for the Human Resources department, adjusting the Target Categories and Source Aliases accordingly.

**2.4. Configure Full Access for Admin Department**

**Objective:** To grant full, unrestricted internet access to the Admin department client (IP address `192.168.20.50`). This demonstrates how to create exceptions to the general content filtering rules for specific users or departments that require full access. **Why create an exception for the Admin department?**  Administrative users often require unrestricted internet access for various tasks, including:

*   System administration and troubleshooting.
*   Accessing online resources for technical information.
*   Downloading software and updates.
*   Responding to security incidents.
    Applying content filtering to administrative users can hinder their ability to perform these essential functions.

**Firewall Rule Configuration:** Create a new firewall rule on the LAN interface *above* the Squid proxy enforcement rule. This rule will bypass the Squid proxy for the Admin client. **Why place the Admin rule *above* the Squid rule?** Firewall rules in pfSense are processed in order from top to bottom. The first rule that *matches* the traffic is applied, and processing stops. By placing the Admin "Pass" rule above the Squid proxy rule, traffic from the Admin client will match the "Pass" rule first, bypass the Squid proxy, and be allowed to access the internet without filtering. If the Squid proxy rule were placed above the Admin rule, Admin client traffic would be caught by the Squid rule first and filtered, negating the full access rule.

![image](https://github.com/user-attachments/assets/90ebcfde-b5df-4901-a6dc-fad846f28c36)

**Firewall Rule Settings Explanation:**

*   **Action:** Set to **"Pass"** to allow traffic. We want to explicitly allow traffic from the Admin client to bypass the proxy.
*   **Interface:** Select **"LAN"**.  This rule is placed on the LAN interface as it applies to traffic originating from within the LAN zone.
*   **Protocol:** Set to **"any"** to allow all protocols.  We want to grant full, unrestricted access, so we allow all protocols for the Admin client.
*   **Source (Src):** Set **"Source"** to **"Single host or alias"** and enter the IP address of the Admin client: `192.168.20.50`.
    *   **Rationale:** By setting the source to the Admin client's IP address, this rule will *only* apply to traffic originating from this specific machine.  Only traffic from the Admin client machine (IP `192.168.20.50`) will match this rule and bypass the Squid proxy.
*   **Destination (Des):** Set **"Destination"** to **"any"** to allow access to any destination network or IP address.
    *   **Rationale:** This rule allows unrestricted access to *any* destination, effectively bypassing the Squid proxy filtering for the Admin client. The Admin client will be able to access any website or internet service without content filtering.

**Rule Placement is Crucial:**  Ensure that this "Admin Full Access" rule is placed *above* the Squid proxy enforcement rule in the firewall rule list. Firewall rules are processed in order from top to bottom.  If the Squid proxy rule were above the Admin rule, the Admin client traffic would be caught by the Squid rule first and filtered, negating the full access rule.  **How to adjust rule order in pfSense?** You can drag and drop firewall rules in the pfSense web interface to change their order.

**Testing Admin Access and General LAN Access:**

![image](https://github.com/user-attachments/assets/fe5e5078-25aa-42aa-b61a-99d62a249f86)

**Testing Procedure:**

1.  **Admin Client (192.168.20.50):** Configure the Admin client machine (IP `192.168.20.50`) to *not* use a proxy server (set "No Proxy"). Attempt to access various websites, including `youtube.com`. Access should be successful to all websites, demonstrating full internet access. **Why test without a proxy for the Admin client?** The "Admin Full Access" rule is designed to *bypass* the Squid proxy filtering. Therefore, the Admin client should be able to access the internet directly, without needing to be configured to use the proxy.

![image](https://github.com/user-attachments/assets/91cf2777-2288-4023-a724-7cc2f684b181)

2.  **Test Client Outside Admin Range (192.168.20.60):** Use a client machine with an IP address outside the Admin IP (e.g., `192.168.20.60`, belonging to the Project department). Configure this client's browser to use the Squid proxy (pfSense LAN IP as proxy, port 3128). Attempt to access `youtube.com`. Access should be blocked, demonstrating that clients outside the Admin IP still have content filtering enforced by the Squid proxy. This confirms that the exception for the Admin client is working correctly and that content filtering is still enforced for other departments.

**Total Firewall Rules - LAN Interface:**

![image](https://github.com/user-attachments/assets/d063d621-39c0-4fbc-9eea-74c3a98ca1f6)

This screenshot shows the complete set of firewall rules on the LAN interface, including the department-specific Squid proxy rules and the Admin full access rule placed at the top.  The order of these rules is critical for proper functionality.

---

## 3. Opening Ports for Specific Services

**Objective:** To demonstrate how to open specific ports on the pfSense firewall to allow access to services running in the LAN and DMZ zones. This is essential for enabling legitimate network services while maintaining firewall security by only opening necessary ports. **Why open specific ports selectively?** Opening only necessary ports is a fundamental security principle known as "least privilege" or "port minimization". It reduces the attack surface of your network by:

*   **Limiting Potential Entry Points:**  Fewer open ports mean fewer potential pathways for attackers to gain access to your network or systems.
*   **Reducing Vulnerability Exposure:**  Services running on open ports can have vulnerabilities. By only opening necessary ports, you minimize the exposure to potential vulnerabilities in unnecessary services.
*   **Improving Firewall Efficiency:**  Fewer rules and ports to process can improve firewall performance and efficiency.

**3.1. Open LAN Ports (Mail, FTP, SMB)**

**Scenario:**  We want to allow external access to mail services (SMTP, POP3, IMAP), FTP, and SMB services that might be running on servers within the LAN zone.  **Caution:** Opening SMB (ports 139, 445) to the internet is generally **highly discouraged** due to significant security risks. This is for lab demonstration purposes only and should **not** be done in a production environment. **Why is opening SMB to the internet risky?** SMB (Server Message Block) is a file-sharing protocol that has historically been vulnerable to numerous security exploits, including ransomware attacks and worms. Exposing SMB directly to the internet significantly increases the risk of these attacks. In production environments, secure alternatives like VPNs or SFTP should be used for remote file access.

**3.1.1. Create Alias for LAN Mail Ports**

**Navigation:** Navigate to **Firewall -> Aliases**.

**Adding Alias:** Click **"+ Add"** to create a new Alias.

**Alias Configuration:** Create an Alias named `Lan_mail_port` to contain the ports commonly used for mail services: `21 (FTP), 25 (SMTP), 110 (POP3), 143 (IMAP)`.

![image](https://github.com/user-attachments/assets/fc316e6d-3d5f-4a6b-97e1-dc0e9681175b)

**Alias Settings Explanation:**

*   **Name:** Set the Alias name to `Lan_mail_port`.  Using a descriptive name helps identify the purpose of this port Alias.
*   **Type:** Choose **"Ports"** as we are defining a group of ports.  Selecting "Ports" indicates that this Alias will represent a collection of port numbers.
*   **Ports:** Enter the port numbers: `21, 25, 110, 143`.  These are common ports associated with:
    *   `21`: FTP (File Transfer Protocol) - Control channel.
    *   `25`: SMTP (Simple Mail Transfer Protocol) - For sending email.
    *   `110`: POP3 (Post Office Protocol version 3) - For receiving email.
    *   `143`: IMAP (Internet Message Access Protocol) - For receiving and managing email.

**3.1.2. Create NAT Port Forwarding Rule for LAN Ports**

**Navigation:** Navigate to **Firewall -> NAT -> Port Forward**.

**Adding NAT Rule:** Click **"+ Add"** to create a new Port Forward rule.

**NAT Rule Configuration:** Create a NAT rule to forward traffic arriving on the WAN interface on the ports defined in the `Lan_mail_port` alias to the LAN network.

![image](https://github.com/user-attachments/assets/9e1a7572-c0a9-48cc-be50-d2c55eeb2e71)

**NAT Rule Settings Explanation:**

*   **A: Source (Src):** Set to **"any"**. This means that traffic originating from *any* source IP address on the internet will be allowed to trigger this port forward rule.
    *   **Rationale:** Setting the source to "any" makes these services publicly accessible from the internet.  Users from anywhere on the internet will be able to attempt to connect to these services through the pfSense WAN IP. In a real-world scenario, you might want to restrict the source to specific IP addresses or networks for security reasons, for example, only allowing access from known partner networks or authorized users through VPNs.
*   **B: Destination port range (Des port range):** Select the **"Lan_mail_port"** Alias we created. This specifies that this rule applies to traffic arriving on the ports defined in the `Lan_mail_port` alias on the WAN interface.
    *   **Rationale:** This ensures that only traffic targeting the specified mail, FTP, and SMB ports will be forwarded.  Traffic arriving on other ports on the WAN IP will not be forwarded by this rule.
*   **C: Redirect target IP:** Set to **"Lan_address"**. This is a special pfSense Alias that represents the entire LAN network subnet (`192.168.20.0/24` in our setup).
    *   **Rationale:** Using `Lan_address` as the redirect target means that the firewall will forward traffic arriving on the specified ports on the WAN interface to *any* IP address within the LAN network subnet.  **Caution:** This is generally not recommended for security reasons. In a production environment, you should typically forward traffic to a *specific server* within the LAN that is intended to host these services, not to the entire LAN subnet.  Forwarding to the entire LAN subnet is a simplified configuration used here for lab demonstration purposes. In a real-world scenario, you would forward to the specific IP of the server hosting the mail, FTP, and SMB services.

**Testing LAN Port Opening:**

![image](https://github.com/user-attachments/assets/1ac93eb2-a12a-459c-9f7b-4109ca67734c)

**Testing Procedure:**

1.  **LAN Server (Metasploitable 2 - 192.168.20.100):** Use a machine within the LAN network (e.g., Metasploitable 2 at `192.168.20.100`) to act as a test server. Ensure that services like FTP and SMTP are running on this machine (Metasploitable 2 has many services running by default).  Metasploitable 2 is used as a convenient test server within the LAN zone, even though it doesn't specifically host mail services in a typical scenario.
2.  **External Tester (Kali Linux - 192.168.40.50 - DTB Zone):** Use a machine outside the LAN zone (e.g., Kali Linux in the DTB zone at `192.168.40.50`) to test port connectivity to the LAN server through the pfSense firewall's WAN IP address.  Use a port scanning tool like `nmap`. Kali Linux, located in the DTB zone, is used as an external testing machine to simulate internet access and verify that the port forwarding rule is working from outside the LAN.
3.  **Port Scan Command:** From Kali Linux, run `nmap -p21,25,110,143,30 <pfSense_WAN_IP>`. Replace `<pfSense_WAN_IP>` with the actual WAN IP address of your pfSense firewall.  This `nmap` command instructs Kali Linux to scan the specified ports (21, 25, 110, 143, and 30) on the pfSense WAN IP address to check their status (open, closed, filtered).
4.  **Analyze `nmap` Output:** Examine the `nmap` output. You should see that ports `21`, `25`, `110`, and `143` (defined in the `Lan_mail_port` alias) are reported as "open", indicating that the NAT port forwarding rule is working.  Port `30` (which is not in the alias) should be reported as "filtered", demonstrating that only the specified ports are open.  `nmap` output provides the port status, allowing you to verify if the firewall rule is correctly opening the intended ports and blocking others.

![image](https://github.com/user-attachments/assets/dbb8a653-2e1e-4e3d-b161-5695ab82a18d)

**Test Result:** The `nmap` scan confirms that the specified mail, FTP, and SMTP ports (21, 25, 110, 143) are open on the pfSense WAN IP and are forwarding traffic to the LAN network, while port 30 is filtered.  This successful test indicates that the NAT port forwarding rule is correctly configured to open the desired ports and forward traffic to the LAN zone.

**3.2. Open Ports for DMZ to Database (DTB) at ports (3306, 3307, 3308)**

**Scenario:** We want to allow database servers in the DMZ zone to communicate with database servers in the DTB (Database) zone on specific database ports (3306, 3307, 3308 - simulating MySQL/MariaDB ports). This demonstrates how to control inter-zone traffic and restrict communication to only necessary ports for specific services. **Why control traffic between DMZ and DTB?**  The DMZ and DTB zones are designed to be separated for security reasons. However, legitimate communication between these zones is often necessary. For example, a web application in the DMZ might need to access a database server in the DTB zone. Controlling this inter-zone traffic is essential to:

*   **Enforce Zone Segmentation:** Maintain the security isolation between zones by only allowing necessary traffic to cross zone boundaries.
*   **Limit Lateral Movement:**  Prevent attackers who compromise a DMZ server from easily accessing the more sensitive database servers in the DTB zone.
*   **Apply Least Privilege:** Only open the specific ports needed for legitimate database communication, minimizing the attack surface and potential vulnerabilities.

**3.2.1. Create Alias for DMZ to DTB Ports and IPs**

**Navigation:** Navigate to **Firewall -> Aliases**.

**Adding Alias:** Click **"+ Add"** to create new Aliases.

**Alias Configuration:** Create the following Aliases:

*   **`DMZ_to_DTB_ports`:**  Type "Ports", Ports: `3306, 3307, 3308` (for database ports).
*   **`DTB_address`:** Type "Network(s)", Network(s): `192.168.40.0/24` (representing the DTB network zone).
*   **`DMZ_address`:** Type "Network(s)", Network(s): `192.168.30.0/24` (representing the DMZ network zone).

![image](https://github.com/user-attachments/assets/6e05d596-9e33-43bf-99ca-23e1540f1126)

**Alias Settings Explanation:**

*   **`DMZ_to_DTB_ports`:**  Defines the ports allowed for communication between DMZ and DTB.  This Alias groups together the common ports used by database services like MySQL/MariaDB.
*   **`DTB_address`:**  Represents the entire DTB network subnet.  This Alias defines the destination network for the firewall rule, representing all machines within the Database Zone.
*   **`DMZ_address`:** Represents the entire DMZ network subnet.  This Alias defines the source network for the firewall rule, representing all machines within the Demilitarized Zone.

**3.2.2. Create Firewall Rule for DMZ to DTB Ports**

**Navigation:** Navigate to **Firewall -> Rules -> DMZ**. We will create a firewall rule on the DMZ interface to allow traffic to the DTB zone on the specified ports.  **Why place the rule on the DMZ interface?** Firewall rules are typically placed on the interface where traffic *enters* the firewall zone. In this case, traffic from the DMZ zone to the DTB zone *originates* from the DMZ zone. Therefore, the rule is placed on the DMZ interface to control outbound traffic from the DMZ to the DTB.

**Adding Firewall Rule:** Click **"+ Add"** to create a new Firewall Rule.

**Firewall Rule Configuration:** Create a firewall rule on the DMZ interface to allow traffic to the DTB network on ports defined in the `DMZ_to_DTB_ports` alias.

![image](https://github.com/user-attachments/assets/7739c651-94b2-4a8d-8283-f1f31b35176f)

**Firewall Rule Settings Explanation:**

*   **Action:** Set to **"Pass"** to allow traffic. We are creating a rule to *permit* communication between the DMZ and DTB zones on specific ports.
*   **Interface:** Select **"DMZ"** as this rule applies to traffic originating from the DMZ zone.  The rule will be placed on the DMZ interface to control traffic as it leaves the DMZ zone towards the DTB zone.
*   **Protocol:** Set to **"TCP"** as database traffic is typically TCP-based. Database protocols like MySQL/MariaDB primarily use TCP for communication.
*   **Source (Src):** Set **"Source"** to **"Network"** and select the `DMZ_address` alias. This means this rule applies to traffic originating from the DMZ network zone.
    *   **Rationale:** Restricting the source to the `DMZ_address` ensures that only traffic originating from the DMZ zone can trigger this rule.  Only traffic from machines within the DMZ network subnet will be evaluated against this rule.
*   **Destination (Destination):** Set **"Destination"** to **"Network"** and select the `DTB_address` alias. This specifies that the traffic is destined for the DTB network zone.
    *   **Rationale:** Restricting the destination to the `DTB_address` ensures that this rule only allows traffic going *from* the DMZ *to* the DTB zone, enforcing zone-based security.  Traffic destined for networks other than the DTB zone will not be matched by this rule.
*   **Destination port range:** Select the **"DMZ_to_DTB_ports"** Alias. This specifies that only traffic destined for the ports defined in this alias (3306, 3307, 3308) will be allowed.
    *   **Rationale:**  Restricting the destination port range to the database ports ensures that only database-related traffic is allowed between the DMZ and DTB zones, minimizing the attack surface and enforcing the principle of least privilege.  Only traffic destined for ports 3306, 3307, and 3308 will be permitted by this rule. Traffic to other ports will be implicitly denied by the default deny rule or other rules.

**Testing DMZ to DTB Port Opening:**

![image](https://github.com/user-attachments/assets/454caba8-0c4a-44f7-875e-5d4b7b78a53c)
![image](https://github.com/user-attachments/assets/a0386233-e395-4506-9323-9fe6045a2047)

**Testing Procedure:**

1.  **DTB Server (Metasploitable 2 - 192.168.40.100):** Use a machine in the DTB zone (Metasploitable 2 at `192.168.40.100`) as the target database server (although Metasploitable 2 doesn't have a running database server by default, it serves as a target IP in the DTB zone).  Metasploitable 2 is used as a convenient test target within the DTB zone, even though it doesn't specifically host a database server in this lab.
2.  **DMZ Tester (Kali Linux - 192.168.30.50 - DMZ Zone):** Use a machine in the DMZ zone (Kali Linux at `192.168.30.50`) to test port connectivity to the DTB server. Use `nmap`. Kali Linux, located in the DMZ zone, is used as a testing machine to simulate a web server or application server in the DMZ attempting to connect to a database server in the DTB zone.
3.  **Port Scan Command:** From Kali Linux, run `nmap -p3306-3308,97 192.168.40.100`. This scans ports 3306, 3307, 3308 (defined in the alias) and port 97 (to test a port *not* in the alias).  This `nmap` command instructs Kali Linux to scan the specified ports (3306-3308 and 97) on the DTB server IP address (`192.168.40.100`) to check their status from within the DMZ zone.
4.  **Analyze `nmap` Output:** Examine the `nmap` output. Ports `3306`, `3307`, and `3308` should be reported as "open", while port `97` should be "filtered".  `nmap` output will show the status of the scanned ports, allowing you to verify if the firewall rule is correctly allowing database port traffic and blocking other traffic between the DMZ and DTB zones.

**Test Result:** The `nmap` scan confirms that ports 3306, 3307, and 3308 are open from the DMZ zone to the DTB zone, while port 97 is filtered, as expected.  This successful test verifies that the firewall rule is correctly allowing database port traffic between the DMZ and DTB zones while blocking other traffic, enforcing inter-zone security policies.

**3.3. Open Ports for Admin to Database (DTB) with ports (22, 23, 3389, 3390)**

**Scenario:** We want to allow the Admin client (located in the LAN zone) to access database servers in the DTB zone for administrative purposes, but only on specific administrative ports (22 - SSH, 23 - Telnet, 3389 - RDP, 3390 - Custom RDP port). **Caution:** Opening Telnet (port 23) and RDP (ports 3389, 3390) to a wide range of sources is generally **insecure**. This is for lab demonstration and should **not** be done in production without strong security measures. **Why limit Admin access to specific ports?** Even for administrative access, it's a security best practice to limit access to only necessary ports. This principle of least privilege applies even to administrative users. Restricting administrative access to specific ports like SSH, RDP, and custom administrative ports:

*   **Reduces Attack Surface:** Limits the number of ports exposed for potential exploitation, even for administrative access.
*   **Enforces Controlled Access:** Ensures that administrative access is only possible through the intended administrative protocols and ports, preventing accidental or unauthorized access through other services.
*   **Improves Auditing and Monitoring:**  Makes it easier to monitor and audit administrative access attempts, as traffic is limited to specific ports and protocols.

**3.3.1. Create Alias for Admin to DTB Ports**

**Navigation:** Navigate to **Firewall -> Aliases**.

**Adding Alias:** Click **"+ Add"** to create a new Alias.

**Alias Configuration:** Create an Alias named `Admin_to_DTB_ports` to contain the administrative ports: `22 (SSH), 23 (Telnet), 3389 (RDP), 3390 (Custom RDP)`.

![image](https://github.com/user-attachments/assets/cd463564-88e8-4ace-aeeb-a545ef0f8154)

**Alias Settings Explanation:**

*   **Name:** Set the Alias name to `Admin_to_DTB_ports`. A descriptive name helps identify the purpose of this port Alias, indicating that it's for administrative access from the Admin client to the DTB zone.
*   **Type:** Choose **"Ports"**. Selecting "Ports" indicates that this Alias will group together a collection of port numbers.
*   **Ports:** Enter the port numbers: `22, 23, 3389, 3390`. These are common ports associated with administrative access:
    *   `22`: SSH (Secure Shell) - For secure remote command-line access.
    *   `23`: Telnet - For remote command-line access (unencrypted - **insecure**, used for lab demonstration only).
    *   `3389`: RDP (Remote Desktop Protocol) - Standard port for Windows Remote Desktop.
    *   `3390`: Custom RDP Port - Demonstrates using a non-standard RDP port for potentially slightly improved security through obscurity (though security through obscurity is not a strong security measure on its own).

**3.3.2. Create Firewall Rule for Admin to DTB Ports**

**Navigation:** Navigate to **Firewall -> Rules -> LAN**. We will create a firewall rule on the LAN interface to allow traffic from the Admin client to the DTB zone on the specified ports. **Why place the rule on the LAN interface?**  The Admin client is located in the LAN zone, and traffic *originates* from the LAN zone when the Admin client attempts to connect to the DTB zone. Therefore, the firewall rule is placed on the LAN interface to control outbound traffic from the LAN to the DTB, specifically from the Admin client.

**Adding Firewall Rule:** Click **"+ Add"** to create a new Firewall Rule.

**Firewall Rule Configuration:** Create a firewall rule on the LAN interface to allow traffic from the Admin client (IP `192.168.20.50`) to the DTB network on ports defined in the `Admin_to_DTB_ports` alias.

![image](https://github.com/user-attachments/assets/129346db-4371-4036-9602-a525a01a2d30)

**Firewall Rule Settings Explanation:**

*   **Action:** Set to **"Pass"** to allow traffic. We are creating a rule to *permit* administrative access from the Admin client to the DTB zone on specific ports.
*   **Interface:** Select **"LAN"** as this rule applies to traffic originating from the LAN zone (specifically from the Admin client in the LAN).  The rule will be placed on the LAN interface to control outbound traffic as it leaves the LAN zone towards the DTB zone.
*   **Protocol:** Set to **"TCP"** as these administrative protocols are TCP-based. SSH, Telnet, and RDP all primarily use TCP for communication.
*   **Source (Src):** Set **"Source"** to **"Single host or alias"** and enter the IP address of the Admin client: `192.168.20.50`.
    *   **Rationale:** Restricting the source to the Admin client's IP ensures that only traffic from the Admin machine can trigger this rule, limiting access to privileged administrative ports.  Only traffic originating from the Admin client machine (IP `192.168.20.50`) will be evaluated against this rule.
*   **Destination (Destination):** Set **"Destination"** to **"Network"** and select the `DTB_address` alias. This specifies that the traffic is destined for the DTB network zone.
    *   **Rationale:** Restricting the destination to the `DTB_address` ensures that this rule only allows traffic going *from* the Admin client *to* the DTB zone, enforcing zone-based security. Traffic destined for networks other than the DTB zone will not be matched by this rule.
*   **Destination port range:** Select the **"Admin_to_DTB_ports"** Alias. This specifies that only traffic destined for the ports defined in this alias (22, 23, 3389, 3390) will be allowed.
    *   **Rationale:** Restricting the destination port range to administrative ports limits the exposure of the DTB zone and enforces the principle of least privilege, allowing admin access only through necessary ports.  Only traffic destined for ports 22, 23, 3389, and 3390 will be permitted by this rule. Traffic to other ports will be implicitly denied.

**Testing Admin to DTB Port Opening:**

![image](https://github.com/user-attachments/assets/fe5b27c0-c811-4f1b-a151-3ed2fe0eb811)

**Testing Procedure:**

1.  **DTB Server (Metasploitable 2 - 192.168.40.100):** Use a machine in the DTB zone (Metasploitable 2 at `192.168.40.100`) as the target server. Ensure services like SSH, Telnet, and RDP are running (Metasploitable 2 has Telnet and RDP running by default, SSH might need to be enabled).  Metasploitable 2 is used as a target server within the DTB zone for testing administrative port access, even though it's not specifically configured as a database server in this scenario.
2.  **Admin Tester (Kali Linux - 192.168.20.50 - LAN Zone):** Use the Admin client machine in the LAN zone (Kali Linux at `192.168.20.50`) to test port connectivity to the DTB server. Use `nmap`. Kali Linux, acting as the Admin client, is used to test connectivity to the DTB server on administrative ports.
3.  **Port Scan Command (Admin Client):** From the Admin client (Kali Linux at `192.168.20.50`), run `nmap -p22,23,3389,3390,97 192.168.40.100`.  This `nmap` command instructs Kali Linux (Admin client) to scan the specified ports (22, 23, 3389, 3390, and 97) on the DTB server IP address (`192.168.40.100`) to check their status from the Admin client's perspective.
4.  **Analyze `nmap` Output (Admin Client):** Examine the `nmap` output from the Admin client. Ports `22`, `23`, `3389`, and `3390` should be reported as "open".  `nmap` output from the Admin client should confirm that the firewall rule is correctly opening the intended administrative ports for access from the Admin client to the DTB zone.

![image](https://github.com/user-attachments/assets/a467b3c1-5ad2-4e7c-9423-0ab58fae0053)

**Test Result (Admin Client):** The `nmap` scan from the Admin client confirms that ports 22, 23, 3389, and 3390 are open from the Admin client to the DTB zone. This successful test verifies that administrative access to the DTB zone is permitted from the Admin client on the specified administrative ports.

**Testing Non-Admin Client Access (LAN Zone - 192.168.20.60):**

![image](https://github.com/user-attachments/assets/7e4b8cea-1d67-4cf3-ac54-a8ce5ee15b61)

**Testing Procedure:**

1.  **Non-Admin Tester (Kali Linux - 192.168.20.60 - LAN Zone):** Use a machine in the LAN zone but *not* the Admin client (Kali Linux at `192.168.20.60`).  Kali Linux, acting as a non-Admin client, is used to test that administrative port access is *denied* for clients other than the designated Admin client.
2.  **Port Scan Command (Non-Admin Client):** From this non-Admin client, run the same `nmap` command: `nmap -p22,23,3389,3390,97 192.168.40.100`.  This `nmap` command instructs Kali Linux (non-Admin client) to scan the same administrative ports on the DTB server IP address.
3.  **Analyze `nmap` Output (Non-Admin Client):** Examine the `nmap` output. Ports `22`, `23`, `3389`, and `3390` should be reported as "filtered".  `nmap` output from the non-Admin client should confirm that the administrative ports are *not* open for clients other than the designated Admin client, demonstrating access control based on source IP.

**Test Result (Non-Admin Client):** The `nmap` scan from the non-Admin client confirms that ports 22, 23, 3389, and 3390 are "filtered", demonstrating that these ports are *not* open for clients other than the designated Admin client, enforcing access control based on source IP.  This successful test verifies that administrative access to the DTB zone is restricted to only the designated Admin client.

---

## 4. Backup Firewall Rules

**Objective:** To demonstrate how to backup the pfSense firewall rules configuration. Regularly backing up your pfSense firewall configuration is crucial for disaster recovery, configuration management, and reverting to previous configurations if needed. **Why backup firewall configurations?** Regular backups are essential for:

*   **Disaster Recovery:**  In case of hardware failure, system corruption, or accidental configuration changes, backups allow you to quickly restore the firewall to a known working state, minimizing downtime.
*   **Configuration Management:** Backups provide a history of firewall configurations, allowing you to track changes, revert to previous configurations if needed, and compare different configurations.
*   **Auditing and Compliance:** Backups can be used for security audits and compliance purposes, providing a record of firewall configurations over time.
*   **Testing and Rollback:** Before making significant configuration changes, creating a backup allows you to easily rollback to the previous configuration if the changes cause issues.

**Navigation:** Navigate to **Diagnostics -> Backup & Restore**.

**Backup and Restore Section:** This section in pfSense allows you to backup and restore the firewall configuration, including rules, NAT settings, and other configurations.

![image](https://github.com/user-attachments/assets/0999b913-f394-423f-bc98-f3b96acee039)

**Backup Procedure:**

1.  **Download Configuration File:** Click **"Download configuration as XML"** (item **1** in the image). This will download the current pfSense configuration as an XML file. Store this file in a secure and accessible location, ideally off-site or on a separate secure storage system.
    *   **Rationale:** Downloading the configuration file creates a backup copy of your firewall rules and settings, allowing you to restore them later if needed.  Storing the backup file securely and off-site protects it from being lost or compromised in case of a local system failure or security breach.
2.  **Backup File Location:** Note the **"Backup area"** section (item **2** in the image). This section shows the file path where pfSense stores its configuration backups internally on the firewall itself (`/cf/conf/backup/`). You can access these files directly from the pfSense console if needed, for example, using SSH access to the pfSense firewall and navigating to this directory in the command line.
    *   **Rationale:**  pfSense automatically creates internal backups of the configuration at regular intervals or after configuration changes. Knowing the backup file location allows you to access these backups directly from the firewall console for local restoration if necessary, even if the web interface is unavailable.

![image](https://github.com/user-attachments/assets/305c0146-63b4-4a7a-81b4-604ce529760b)

**Restore Procedure:**

1.  **Browse and Select Backup File:** In the "Restore" section, click **"Browse"** to locate and select a previously downloaded pfSense configuration XML backup file.  You will need to upload the backup file from your local machine to the pfSense firewall through the web interface.
2.  **Restore Configuration:** Select the backup file and click **"Restore Configuration"** (button labeled "Restore" in item **3** of the image).
    *   **Rationale:**  The "Restore Configuration" action will load the selected backup file and apply the configurations contained within it to the pfSense firewall, effectively reverting the firewall to the state it was in when the backup was created.  This action will overwrite the current firewall configuration with the settings from the backup file.

![image](https://github.com/user-attachments/assets/014c6deb-35b0-4ccf-ac8a-b64112d4e5f7)

**Restore Confirmation:** After clicking "Restore", pfSense will apply the configuration and typically reboot to ensure all settings are properly loaded.  **Why does pfSense reboot after restore?**  Rebooting after restoring the configuration ensures that all services and components of pfSense are restarted and reloaded with the new configuration, guaranteeing that all settings are properly applied and active. After the restore process is complete, the firewall rules and settings will be reverted to the backed-up state. You should verify the restored configuration to ensure it is as expected.

---
</details>

<details>
   <summary>PfSense Firewall Model 2</summary>

   
# PfSense Firewall Configuration: Realistic Lab Simulation 2

**Purpose:** This report outlines the configuration of a pfSense system, detailing firewall rules, proxy settings, and other configurations implemented in a realistic lab simulation. The goal is to demonstrate practical firewall management tasks and enhance understanding of network security principles using pfSense version 2.7.2-RELEASE (amd64). This lab is designed to provide hands-on experience with essential firewall functionalities in a segmented network environment.

**Set Up:** The pfSense system is running version 2.7.2-RELEASE (amd64). The network interface configuration is as follows, creating a segmented network environment with WAN, LAN, DMZ, and DTB zones for enhanced security and controlled traffic flow. Network segmentation is a core security principle to isolate network segments and limit the impact of potential breaches.

![image](https://github.com/user-attachments/assets/eb56b5a1-154e-4785-a5db-29a5b87c6c1a)

| Interface | Interface Name | IP Address         | Description                                                                                                                                                                                                                            |
| --------- | -------------- | ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| WAN       | em0            | 192.168.19.10/24   | **WAN (Wide Area Network):** Interface `em0` is assigned to the WAN zone and has IP address `192.168.19.10/24`. This interface **simulates the connection of pfSense to the internet or external, untrusted networks**. It represents the public-facing side of the firewall. |
| LAN       | em1            | 192.168.20.10/24   | **LAN (Local Area Network):** Interface `em1` is assigned to the LAN zone and has IP address `192.168.20.10/24`. This interface **represents the trusted internal network**, connecting pfSense to internal devices like employee computers, printers, and internal servers. This is the protected internal network.         |
| DMZ       | em2 (opt1)     | 192.168.30.10/24   | **DMZ (Demilitarized Zone):** Interface `em2 (opt1)` is assigned to the DMZ zone and has IP address `192.168.30.10/24`. The DMZ is a **security zone placed between the LAN and WAN**. It is designed to **host public-facing servers** such as web servers, mail servers, and application servers, providing a buffer between the internet and the more secure LAN.                               |
| DTB       | em3 (OTP2)     | 192.168.40.10/24   | **DTB (Data Zone):** Interface `em3 (OTP2)` is assigned to the DTB zone and has IP address `192.168.40.10/24`. The DTB zone is **dedicated to hosting database servers or other sensitive data repositories**, providing an additional layer of security by isolating critical data assets. This is the most sensitive zone, requiring the strictest security controls.                   |

The current network configuration of pfSense demonstrates the system being used to segment the network into distinct security zones (WAN, LAN, DMZ, DTB). **This segmentation enhances security by isolating different network segments and enabling granular control over traffic flow between these zones**, following best practices for network security architecture.  This setup allows for the implementation of different security policies for each zone based on its specific risk profile and function, adhering to the principle of least privilege and defense in depth.

## 1. Initial Check: Default Firewall Rules

The default rules for the LAN and DMZ interfaces in pfSense are pre-configured with different security postures, reflecting common security practices for these zones. Understanding these defaults is crucial before customizing firewall rules.

![image](https://github.com/user-attachments/assets/96b24fc5-d159-49fa-a576-75dd359709bb)

**Default LAN Rule - Allow All Outbound:**

By default, the LAN zone has a pre-existing rule that *allows all outbound traffic*. This is a common default configuration for LAN zones in firewalls, assuming that internal LAN devices should have relatively unrestricted access to external networks, including the internet. This default rule prioritizes ease of use for internal users.

![image](https://github.com/user-attachments/assets/5b036c25-4654-4ed2-98d5-94847b2b0d58)

**Rationale:**  The default "allow all outbound" rule for LAN is intended for ease of use and assumes a trusted internal network. However, in real-world scenarios, it's **crucial to review and refine this default rule** to implement more restrictive outbound policies based on security requirements and the principle of least privilege.  A "zero-trust" approach would advocate for even more restrictive outbound rules from the LAN.

**Default DMZ Rule - No Default Allow Rule (Implicit Deny):**

For the DMZ zone, there is *no default "allow all outbound" rule*. This means that by default, the DMZ zone has an *implicit deny all outbound* policy.  Without explicit allow rules, traffic originating from the DMZ zone will be blocked by the firewall's default deny behavior. This default posture prioritizes security for the DMZ.

![image](https://github.com/user-attachments/assets/46fbf21c-a635-44dd-a7c7-7ba67925e732)

**Rationale:** The default "implicit deny" policy for the DMZ is a security best practice. DMZ zones are intended to host public-facing servers, and outbound traffic from the DMZ should be strictly controlled and limited to only necessary communication.  This default deny posture helps to **minimize the potential for compromised DMZ servers to be used for outbound attacks or data exfiltration**, adhering to the principle of least privilege and minimizing the attack surface.

## 1. Allowing DMZ to Access the Internet

To enable internet access for servers in the DMZ zone (which is often required for software updates, external service dependencies, or certain application functionalities), we need to create an explicit firewall rule to allow outbound traffic from the DMZ to the WAN. This rule is necessary for basic server administration and software maintenance in the DMZ.

This rule applies to all IP protocols (IPv4), allowing all packets originating from subnets within the DMZ and destined for any destination. (In simpler terms, this rule grants the DMZ zone the ability to access the internet).

![image](https://github.com/user-attachments/assets/160d4ba0-91e5-4438-8f9c-f1fa0e01d707)

**Firewall Rule Settings Explanation:**

*   **Action:** `Pass` -  This action specifies that traffic matching this rule will be *allowed* through the firewall. This is a permissive rule to enable internet access.
*   **Interface:** `DMZ` -  This rule is applied to the DMZ interface, meaning it controls traffic originating *from* the DMZ zone. This rule governs outbound traffic from the DMZ.
*   **Protocol:** `any` -  Setting the protocol to "any" means this rule applies to *all* IP protocols (TCP, UDP, ICMP, etc.). While convenient for initial setup, it's less secure for production.
*   **Source:** `DMZ net` -  The "Source" is set to "DMZ net," which is a pre-defined Alias in pfSense representing the DMZ network subnet (192.168.30.0/24 in this setup). This means the rule applies to traffic originating from *any* IP address within the DMZ subnet.  This targets the entire DMZ subnet as the source.
*   **Destination:** `any` - The "Destination" is set to "any," meaning this rule applies to traffic destined for *any* IP address or network, including the internet. This is a very broad destination, less secure for production environments.

**Rationale:** This rule, in its current form, is a very broad "allow all outbound" rule for the DMZ. While it achieves the objective of enabling internet access for the DMZ, it's **not a security best practice** for production environments.  It's used here for initial lab setup and demonstration, but should be refined for real-world deployments to adhere to security best practices.

**Save and Test:**

![image](https://github.com/user-attachments/assets/87478476-3acd-474d-820b-c98f931f21df)

After saving the rule, apply the changes to activate the firewall rule. You can test internet access from a virtual machine within the DMZ zone (e.g., by pinging a public IP address or browsing to a website).  Testing is crucial to verify rule effectiveness.

**Caution: Security Implications of Broad "Allow Any" Rule:**

![image](https://github.com/user-attachments/assets/cedc79f2-8a14-47ff-82d7-3b1378f32f29)

**Important Security Consideration:** Because the "Destination" is set to "Any" and the "Protocol" is set to "any" on both cards, this rule is overly permissive. It allows *all* outbound traffic from the DMZ to *any* destination, both inside and outside the network, including potentially risky protocols like ping (ICMP). This broad rule significantly increases the attack surface.

**Security Risk:**  Opening up all destinations and protocols like this increases the attack surface of the DMZ. If a server in the DMZ is compromised, this broad rule could allow an attacker to use the compromised server to launch attacks against other internal networks or external targets using any protocol. This represents a significant security vulnerability.

**Best Practice:** For enhanced security, it's crucial to refine this DMZ outbound rule to only allow *necessary* traffic to *specific* destinations and on *specific* ports. For example, you should typically only allow:  Following the principle of least privilege is paramount.

*   **Outbound HTTPS (port 443) and HTTP (port 80):** For web browsing and accessing web-based services.  Essential for accessing software repositories and online documentation.
*   **Outbound DNS (port 53):** For domain name resolution.  Necessary for resolving domain names to IP addresses, enabling web browsing by URL.
*   **Outbound SSH (port 22):** For secure remote administration (only if necessary and to specific, trusted destinations).  Should be restricted to specific administrator IPs in production.
*   **Restrict ICMP (ping):**  Consider blocking or limiting ICMP traffic, especially outbound ping, as it's often not required for server functionality and can be used for network reconnaissance by attackers. ICMP should generally be blocked unless specifically needed for monitoring or troubleshooting.

## 2. Modifying Rules to Block Ping and Allow Only Ports 22, 80, 443 (Refining DMZ Outbound Access)

To enhance the security of the DMZ outbound rule and adhere to the principle of least privilege, we will modify the rule to:

*   **Restrict protocols:**  Only allow TCP traffic (as HTTP, HTTPS, and SSH are TCP-based). Limiting to TCP reduces the attack surface.
*   **Restrict destination ports:** Only allow destination ports 22, 80, and 443, covering SSH, HTTP, and HTTPS.  Restricting ports limits potential attack vectors.
*   **Implicitly block other protocols and ports:** By not explicitly allowing them, other protocols like ICMP (ping) and other ports will be implicitly blocked by the firewall's default deny behavior.  Implicit deny is a core security principle.

We will demonstrate two methods to achieve this refined rule, showcasing different approaches to firewall rule configuration.

**Method 1: Modifying the Protocol and Destination Port Range Directly**

This method involves directly editing the existing "allow all outbound DMZ" rule and changing its "Protocol" and "Destination Port Range" settings. This is a straightforward approach for simple rule modifications.

Change the Protocol from `any` to `TCP` and the Destination Port Range to the desired ports.

![image](https://github.com/user-attachments/assets/a4607017-5ff5-420b-b3b5-404ceb7ca4fc)

**Rule Settings Explanation (Method 1):**

*   **Protocol:** `TCP` -  Changed from "any" to "TCP" to restrict the rule to only apply to TCP-based traffic.
    *   **Rationale:**  Focusing on TCP is sufficient for allowing web browsing (HTTP/HTTPS) and secure remote administration (SSH), which are the most common outbound communication needs for DMZ servers.  This reduces the allowed protocols, minimizing the attack surface.
*   **Destination port range:** `HTTP,HTTPS,SSH` -  The "Destination port range" is set to `HTTP,HTTPS,SSH`, which translates to ports 80, 443, and 22.
    *   **Rationale:**  Limiting the destination ports to 80, 443, and 22 restricts outbound traffic to only these essential ports, significantly reducing the attack surface and potential for misuse of the DMZ outbound rule. This adheres to the principle of least privilege.

Do the same for the remaining ports (HTTPS and SSH) by adding additional rules, if needed, or by modifying the existing rule to include all desired ports. In a more refined approach, you might create separate rules for each port or service for better granularity and clarity, enhancing rule management.

**Method 2: Using Aliases for Destination Ports (Recommended for Manageability)**

This method is more flexible and manageable, especially when dealing with multiple ports or when you might need to reuse port groups in other firewall rules. We will create an Alias to group the allowed destination ports (22, 80, 443) and then use this Alias in the firewall rule.  Aliases improve rule readability and maintainability.

Create an Alias to group the desired ports.

**Navigation:** Navigate to **Firewall > Aliases > Add**

**Alias Configuration:** Create a new Alias to group the allowed destination ports.

![image](https://github.com/user-attachments/assets/d0f24f56-e9e1-4793-b211-80dc50f5246f)

**Alias Settings Explanation (Method 2 - Alias Creation):**

*   **Name:** `DMZ_Outbound_Ports` -  Choose a descriptive name for the Alias, indicating its purpose (allowed outbound ports for DMZ).  Descriptive names improve rule understanding.
*   **Type:** `Ports` - Select "Ports" as the Alias type, indicating that this Alias will group together port numbers.  Selecting the correct Alias type is essential for proper functionality.
*   **Ports:** `22, 80, 443` - Enter the port numbers that should be allowed for outbound traffic: 22 (SSH), 80 (HTTP), 443 (HTTPS).  This list defines the allowed outbound ports.

Go back to the Firewall Rule and modify it to use the newly created Alias.

**Navigation:** Navigate to **Firewall > Rules > DMZ > Edit the DMZ outbound rule**.

**Firewall Rule Modification:** Modify the existing DMZ outbound rule to use the `DMZ_Outbound_Ports` Alias for the "Destination port range."

![image](https://github.com/user-attachments/assets/49f71959-f234-45e5-a746-7fd159892914)

**Firewall Rule Settings Explanation (Method 2 - Rule Modification):**

*   **Protocol:** `TCP` -  Keep the Protocol set to "TCP". No change needed.
*   **Destination port range:** `DMZ_Outbound_Ports` -  Change the "Destination port range" to select the `DMZ_Outbound_Ports` Alias from the dropdown menu.
    *   **Rationale:** By using the `DMZ_Outbound_Ports` Alias, the firewall rule now dynamically references the ports defined in the Alias. If you need to add or remove allowed ports later, you only need to modify the Alias, and the firewall rule will automatically update. Aliases provide dynamic rule updates, improving maintainability.

**Benefit of Using Aliases (Method 2):**

*   **Convenience:**  Aliases make rules easier to understand and manage by using named objects instead of raw port numbers.  Rule clarity is improved.
*   **Manageability:**  Aliases centralize port definitions.  Updating the allowed ports only requires modifying the Alias, not individual firewall rules.  Rule updates are simplified.
*   **Readability:**  Rules using Aliases are more self-documenting, as the Alias name (`DMZ_Outbound_Ports`) clearly indicates the purpose of the port restriction.  Rule purpose is clearer.
*   **Consistency:**  Ensures consistent port definitions across multiple firewall rules if you reuse the same Alias in different rules.  Rule consistency is enhanced.

**Testing Refined DMZ Outbound Rules:** After applying either Method 1 or Method 2, test outbound connectivity from a VM in the DMZ zone. Verify that: Testing is crucial to confirm rule effectiveness.

*   **Web browsing (HTTP/HTTPS) and SSH access are still working.**  Essential services should remain functional.
*   **Ping (ICMP) to external destinations is now blocked.** Unnecessary protocols should be blocked.
*   **Access to other ports (e.g., Telnet on port 23) is also blocked.**  Non-essential ports should be blocked.

**However, if we only add ports 80 or 443, while we can access the internet in a basic sense, we can only access websites using their IP addresses directly.** We cannot use domain names (URLs) because domain name resolution to IP addresses is not possible, leading to the inability to access the internet using URLs (e.g., `www.google.com`). This limitation highlights the importance of DNS.

**Reason:**  Domain name resolution relies on DNS (Domain Name System), which uses port 53 (both TCP and UDP). If port 53 (DNS) is not allowed in the DMZ outbound rule, DMZ servers cannot perform DNS lookups to resolve domain names to IP addresses. DNS is a fundamental internet service.

**Solution: Add port 53 (DNS) to the Aliases to enable Domain Name Resolution.**

To enable proper internet access using URLs (domain names) for the DMZ zone, we need to allow outbound DNS traffic (port 53) in addition to ports 22, 80, and 443.  Allowing DNS is essential for user-friendly internet access.

**Action:** Modify the `DMZ_Outbound_Ports` Alias to include port 53 (DNS).

**Navigation:** Navigate to **Firewall > Aliases > Edit `DMZ_Outbound_Ports` Alias**.

**Alias Modification:** Add port `53` to the "Ports" list in the `DMZ_Outbound_Ports` Alias.

![image](https://github.com/user-attachments/assets/45875170-a04a-4db2-9df1-218b12c020af)

**Alias Settings Explanation (DNS Port Addition):**

*   **Ports:**  Modify the "Ports" list to include `22, 53, 80, 443`. We are adding port 53 to allow DNS traffic, enabling domain name resolution.  Adding port 53 enables DNS functionality.

**Testing DNS Resolution:** After adding port 53 to the Alias and applying the changes, test internet access from a VM in the DMZ zone again. Verify that: Testing after configuration changes is crucial.

*   **Web browsing using URLs (e.g., `www.google.com`) now works correctly.**  URLs should now resolve and websites should be accessible.
*   **DNS resolution is successful (you can ping domain names).**  DNS resolution should be functional.
*   **Only ports 22, 53, 80, and 443 are allowed outbound from the DMZ (other ports and ICMP should still be blocked).**  Security restrictions should remain in place for other protocols and ports.

**Following this approach, we can customize for other services as needed:**

By using Aliases and creating firewall rules with specific protocols, source zones, destination zones, and port ranges, you can customize firewall configurations for various services and network requirements.  This approach allows for granular control over network traffic and enables you to implement security policies tailored to different services and network segments, adhering to the principle of least privilege and defense in depth. Examples of customizing for other services include: Customization allows for tailored security policies.

*   **Email:** Allowing sending and receiving emails using ports `25 (SMTP), 110 (POP3), 143 (IMAP)`, etc. For email servers in the DMZ, you would create rules to allow inbound SMTP (port 25) and outbound SMTP (port 25), POP3 (port 110), IMAP (port 143) traffic as needed. Email services require specific port allowances.
*   **FTP:** Enabling file transfer using ports `21 (FTP control), 20 (FTP data)`, etc. If you need to allow FTP access to servers in the DMZ, you would create rules to allow inbound FTP control (port 21) and FTP data (port 20 - or passive FTP port range) traffic.  **Caution:** Consider using more secure alternatives like SFTP (SSH File Transfer Protocol) or FTPS (FTP Secure) instead of standard FTP whenever possible, as FTP transmits data and credentials in plain text.  Prioritize secure protocols like SFTP and FTPS over insecure FTP.
*   **VPN:** Allowing VPN connections often use ports like `1723 (PPTP), 4500 (IPsec), 1194 (OpenVPN)`, etc. If you need to allow VPN access to your network, you would create rules to allow inbound traffic on the specific VPN port (e.g., 1194 for OpenVPN) and protocol (e.g., UDP for OpenVPN). VPNs require specific port allowances for secure remote access.
*   **Remote Desktop:** Enabling remote computer access typically uses port `3389 (RDP)`, etc. If you need to allow remote desktop access to systems in the LAN or DMZ, you would create rules to allow inbound RDP traffic (port 3389 or a custom RDP port) from specific trusted source networks or IP addresses.  **Caution:** Exposing RDP directly to the internet is a security risk. Consider using VPNs or other secure remote access solutions instead.  RDP should be carefully controlled due to security risks.
*   **Online Games:** Allowing access for online games often requires opening different ports depending on the specific game.  You would need to identify the port ranges used by the online games you want to support and create firewall rules to allow UDP and/or TCP traffic on those ports. Online games often use dynamic port ranges, requiring careful rule configuration.

## 3. Creating a Rule to Block Ping (ICMP), Blocking All ICMP Traffic from the Internet (WAN) to the LAN Zone

**Purpose:** To mitigate flood attacks and reduce network reconnaissance by blocking ICMP echo request (ping) traffic from the internet (WAN) to the internal LAN network. **Why block Ping (ICMP)?** Blocking ICMP echo requests (pings) from the internet to your internal network provides several security benefits, enhancing network security posture.

*   **DoS Attack Mitigation:**  Blocks simple ICMP flood Denial-of-Service (DoS) attacks that attempt to overwhelm your network with a large volume of ping requests. Prevents basic DoS attacks.
*   **Network Reconnaissance Prevention:**  Prevents external attackers from using ping and traceroute to scan your LAN network, map out active devices, and potentially identify vulnerabilities.  Ping is a basic network reconnaissance tool, blocking it hinders network mapping.
*   **Reduced Information Disclosure:**  Hides the presence of live devices on your LAN from external scanners, making it slightly harder for attackers to map your internal network. Reduces information leakage to external entities.

**Implementation Steps:**

To achieve this, we need to create a firewall rule on the LAN interface to block inbound ICMP traffic from the WAN.  The rule must be placed on the LAN interface to control inbound traffic to the LAN.

**Navigation:** Navigate to **Firewall > Rules > LAN**.

**Adding Firewall Rule:** Click **"+ Add"** to create a new Firewall Rule.

**Firewall Rule Configuration:** Create a rule on the LAN interface to block ICMP traffic from the WAN zone.

![image](image url of corrected rule on LAN interface blocking ICMP from WAN to LAN here)  *(You would need to replace this with a correct image showing the rule on the **LAN** interface, corrected from the original document)*

**Corrected Firewall Rule Settings (For Blocking WAN to LAN Ping):**

*   **Action:** `Block` - Set the action to "Block" to explicitly *deny* ICMP traffic matching this rule. Explicit block action is used.
*   **Interface:** `LAN` **(Corrected Interface)** -  The rule is correctly placed on the **LAN** interface to control inbound traffic to the LAN zone. Correct interface selection is crucial.
*   **Protocol:** `ICMP` - Set the Protocol to "ICMP" to specifically target ICMP traffic (ping and other ICMP messages).  Rule targets ICMP protocol.
*   **Source:** `WAN net` -  Set the "Source" to "WAN net," which represents the WAN network zone (simulating the internet). This means the rule applies to traffic originating from the internet. Rule source is WAN network.
*   **Destination:** `LAN net` - Set the "Destination" to "LAN net," which represents the LAN network zone. This means the rule applies to traffic destined for the LAN network. Rule destination is LAN network.

This section is customizable. Here, we will block all ICMP from WAN to LAN. You can customize this rule further to block only specific types of ICMP messages or to allow ICMP from specific source IP addresses if needed, allowing for granular control over ICMP traffic.

![image](https://github.com/user-attachments/assets/9e37b3b8-eed0-457b-8c5c-713faca9fabc)

**Benefits of the Rules:**

*   **Enhanced Security:** Blocking ICMP from WAN helps prevent attackers from using ping and traceroute to scan the LAN, looking for active devices and security vulnerabilities. This makes it harder for external attackers to map your internal network, improving security posture.
*   **Scope of Impact:** This rule *only* blocks ICMP traffic from the Internet to the LAN. It does *not* affect ICMP traffic between other interfaces (LAN to DMZ, DMZ to LAN, LAN internal, DMZ internal, etc.). Internal ICMP traffic within the LAN or DMZ zones will still be allowed by default unless explicitly blocked by other rules. Rule scope is limited to WAN to LAN ICMP.
*   **Mitigation of Denial-of-Service (DoS) Attacks:** Some DoS attacks utilize ICMP flood, sending a large volume of ICMP traffic to overwhelm the target system. Blocking ICMP from the WAN can help mitigate these simple ICMP flood attacks, although it's not a complete DoS protection solution. Primarily, it's to prevent external attackers from using ping and other ICMP tools for network reconnaissance against the LAN.  DoS mitigation is a secondary benefit, reconnaissance prevention is primary.

**!! However, there is an issue: the DMZ can still ping the LAN.**

After blocking ping from the WAN to the LAN, a potential security concern remains: **If an attacker gains access to a server within the DMZ zone, they can still potentially scan the LAN network using ping because, by default, traffic from the DMZ to the LAN is not blocked.** This is because the DMZ outbound rule we created earlier only restricted traffic *to the internet (WAN)*, not to the internal LAN.  Lateral movement risk remains due to default DMZ to LAN allow policy.

If someone gains access to the DMZ zone, they can scan the LAN because the DMZ can still ping the LAN. They can use ping to scan the LAN, looking for active devices and security vulnerabilities. This lateral movement from a compromised DMZ server to the internal LAN is a significant security risk. Lateral movement allows attackers to expand their foothold.

---> **Solution: Add an ICMP blocking rule to block ping from DMZ to LAN as well.**

To mitigate this lateral movement risk and further enhance security, we should create an additional firewall rule to explicitly block ICMP traffic from the DMZ zone to the LAN zone.  Blocking DMZ to LAN ping further enhances security.

![image](https://github.com/user-attachments/assets/a59ef7fc-75d1-45b3-aef9-d5c3a54e6f58)

**Firewall Rule Configuration (Block DMZ to LAN Ping):**

*   **Action:** `Block` -  Set the action to "Block" to explicitly *deny* ICMP traffic matching this rule. Explicit block action is used.
*   **Interface:** `DMZ` -  This rule is placed on the DMZ interface to control traffic originating *from* the DMZ zone.  Rule is placed on DMZ interface to control outbound traffic from DMZ.
*   **Protocol:** `ICMP` - Set the Protocol to "ICMP" to specifically target ICMP traffic. Rule targets ICMP protocol.
*   **Source:** `DMZ net` - Set the "Source" to "DMZ net," representing the DMZ network subnet.  This rule applies to traffic originating from *any* IP address within the DMZ subnet. Rule source is DMZ network.
*   **Destination:** `LAN net` - Set the "Destination" to "LAN net," representing the LAN network subnet. This rule applies to traffic destined for the LAN network. Rule destination is LAN network.

Create a rule on the DMZ interface with the source as DMZ subnet and the destination as LAN subnet to block all ICMP to the LAN.  This rule will block ICMP traffic originating from the DMZ zone and destined for the LAN zone, enhancing zone isolation.

And then the DMZ will no longer be able to ping the LAN. Enhancing security and further isolating the LAN zone from potential threats originating from a compromised DMZ server. DMZ to LAN ping is now blocked.

**Benefits of Blocking DMZ to LAN Ping:**

*   **More Secure Zone Isolation:**  Enhances the security isolation between the DMZ and LAN zones. By blocking ping, you further restrict communication pathways between these zones, making lateral movement from a compromised DMZ server to the LAN more difficult. Zone isolation is strengthened.
*   **Reduced Lateral Movement Risk:** Makes it harder for an attacker who has compromised a DMZ server to perform network reconnaissance of the internal LAN network using ping sweeps. Lateral movement risk is reduced further.
*   **Defense in Depth:**  Adds another layer of security to the network, contributing to a defense-in-depth security strategy. Defense in depth is enhanced.

**Drawbacks of Blocking ICMP:**

*   **Difficulty in Network Troubleshooting:** Blocking ICMP can sometimes make network troubleshooting more difficult, as ping is a common tool used for basic network diagnostics.  You may need to use alternative tools for network testing and connectivity checks. Troubleshooting can be slightly more complex.
*   **Potential Application/Service Impact:** In rare cases, some legitimate applications or services might rely on ICMP for specific functions (e.g., path MTU discovery). Blocking ICMP might potentially affect these applications, although this is less common for typical server and workstation applications.  Application compatibility issues are rare but possible.

**However, overall, the security benefits of blocking ping from WAN to LAN and DMZ to LAN generally outweigh the risks in most security-conscious environments.**  The reduction in attack surface and mitigation of reconnaissance and DoS risks typically outweigh the minor inconvenience in troubleshooting or potential minor application compatibility issues. Security benefits generally outweigh drawbacks.

In addition to blocking ping from WAN to LAN and DMZ to LAN (mentioned earlier), we can also consider blocking ping from the following directions to further enhance network security, depending on your specific security requirements and risk tolerance:  Further ICMP blocking directions to consider.

1.  **LAN to WAN:**
    *   **Purpose:**
        *   Prevent external attackers from using ping to scan devices in the LAN *via* compromised LAN machines. While direct WAN to LAN ping is blocked, if a LAN machine is compromised, it could potentially initiate ping scans to the WAN. Blocking LAN to WAN ping further reduces this risk. Outbound reconnaissance from LAN is further limited.
        *   Reduce the risk of Denial-of-Service (DoS) attacks originating from outside and being amplified by compromised LAN machines. Outbound DoS amplification from LAN is reduced.
    *   **Note:**
        *   Blocking ping from LAN to WAN may affect some applications or services that need to use ping to check internet connectivity from LAN machines. Legitimate ping usage from LAN might be affected.
        *   If you need to allow some devices in the LAN to ping outwards for legitimate purposes (e.g., network monitoring tools), create a separate rule allowing ping with restricted conditions (e.g., allow ping only to specific destination IPs or for specific source IPs).  Exceptions can be made for legitimate ping needs.

2.  **DMZ to WAN:**
    *   **Purpose:**
        *   Prevent external attackers from using ping to scan servers in the DMZ *via* compromised DMZ servers. Similar to LAN to WAN, blocking DMZ to WAN ping further reduces the potential for compromised DMZ servers to be used for outbound reconnaissance. Outbound reconnaissance from DMZ is further limited.
        *   Reduce the risk of Denial-of-Service (DoS) attacks originating from outside and being amplified by compromised DMZ servers. Outbound DoS amplification from DMZ is reduced.
    *   **Note:**
        *   Blocking ping from DMZ to WAN may affect some applications or services in the DMZ that need to use ping to check internet connectivity.  Legitimate ping usage from DMZ might be affected.
        *   If you need to allow some servers in the DMZ to ping outwards for legitimate purposes (e.g., server monitoring tools), create a separate rule allowing ping with restricted conditions. Exceptions can be made for legitimate ping needs.

3.  **LAN to DMZ (if needed):**
    *   **Purpose:**
        *   Prevent scanning and attacks from the LAN network to the DMZ. Further enhance the isolation and security separation between the LAN and DMZ zones.  While DMZ to LAN traffic is typically more restricted, blocking LAN to DMZ ping further strengthens the zone isolation in both directions. Zone isolation is further strengthened.
    *   **Note:**
        *   Blocking ping from LAN to DMZ may affect some applications or services that need to use ping to connect to servers in the DMZ for legitimate purposes (though this is less common in typical DMZ setups). Legitimate LAN to DMZ ping usage is less common.
        *   Careful consideration is needed before applying this rule, as it may cause more hindrance than blocking ping in other directions and might disrupt legitimate internal communication if not carefully planned. Blocking LAN to DMZ ping is generally less critical than blocking WAN to LAN or DMZ to LAN ping, but can be considered for very high-security environments.  LAN to DMZ ping blocking should be carefully considered for potential impact.

| From | To  | Purpose                                                                     | Recommendation     | Security Benefit Level | Troubleshooting Impact |
| ---- | --- | --------------------------------------------------------------------------- | ------------------ | ------------------------ | ----------------------- |
| WAN  | LAN | Prevent external reconnaissance, DoS                                         | **Should Block**   | High                     | Low                     |
| DMZ  | LAN | Prevent lateral movement, zone isolation                                    | **Should Block**   | High                     | Low                     |
| LAN  | WAN | Prevent outbound reconnaissance, DoS (less critical)                        | **Consider**       | Medium                   | Medium                  |
| DMZ  | WAN | Prevent outbound reconnaissance, DoS (less critical)                        | **Consider**       | Medium                   | Medium                  |
| LAN  | DMZ | Further zone isolation (least critical)                                     | **Consider Carefully** | Low                      | Potentially High        |

## 4. Squid, SquidGuard (squidGuard), Lightsquid (lightsquid) - Web Proxy and Content Filtering Packages

**Installation Issues:**

Downloading via command or interface failed :((

![image](https://github.com/user-attachments/assets/2c1551ac-c01b-4050-9a28-304f8e244882)

**Note:** The document indicates issues with downloading Squid packages. Package installation failures in pfSense can be due to various reasons, including network connectivity problems, DNS resolution issues, package repository problems, or conflicts with existing packages. Troubleshooting package installation issues would involve checking network connectivity, DNS settings, package repository configuration in pfSense, and system logs for error messages. Troubleshooting package installation failures requires systematic investigation.

**Package Explanations (Even without Successful Installation):**

Even though the Squid packages failed to install in this specific lab setup, understanding the purpose and functionality of Squid, SquidGuard, and Lightsquid is crucial for web proxy and content filtering in pfSense. Here's a breakdown of these packages, essential for web traffic management and security.

On pfSense, there are 3 packages related to Squid, each with different functions and purposes, working together to provide a comprehensive web proxy and content filtering solution:  Squid packages provide comprehensive web proxy and filtering.

1.  **Squid (squid):** - The Core Proxy Server
    *   **Function:** Provides the basic proxy server service, handling HTTP and HTTPS proxy requests and communication. Squid is the foundational package that provides the core proxy functionality, acting as the central proxy engine.
    *   **Purpose:**
        *   **Cache Web Content:** Squid acts as a caching proxy server. It stores (caches) frequently accessed web pages, images, and other web content on the pfSense firewall. When users request content that is already in the cache, Squid serves the content directly from its cache, rather than fetching it again from the internet.  **Benefits of Caching:** Caching improves performance and reduces bandwidth usage.
            *   **Improved Web Browsing Speed:**  Faster page load times for frequently accessed content, as content is served from the local cache instead of the remote web server. Web browsing speed is improved through caching.
            *   **Reduced Bandwidth Consumption:**  Decreases internet bandwidth usage by serving cached content, especially for commonly accessed websites and resources. Bandwidth consumption is reduced through caching.
        *   **Control Web Access:** Squid provides basic access control features, allowing you to configure rules to block or allow access to specific websites, domains, or URLs.  Squid's access controls can be based on source IP addresses, destination URLs, and other criteria. Basic web access control is provided.
        *   **User Authentication:** Squid can be configured to require users to authenticate (username/password) before they can access the internet through the proxy. This is useful for user-based access control, usage tracking, and security. User authentication can be enforced through Squid.

2.  **SquidGuard (squidGuard):** - Advanced Content Filtering Extension for Squid
    *   **Function:** Provides advanced web content filtering features that extend the basic access control capabilities of Squid. SquidGuard works as a URL redirector and filter plugin for Squid, enhancing its content filtering capabilities significantly. SquidGuard enhances Squid's content filtering capabilities.
    *   **Purpose:**
        *   **Block Inappropriate Websites:** SquidGuard uses blacklists (URL category databases) to categorize websites into different categories (e.g., "Adult," "Gambling," "Social Media," "News," etc.). It allows you to easily block access to entire categories of websites based on their content, enabling effective content filtering for inappropriate or unwanted websites. Website category blocking is enabled through blacklists.
        *   **Categorize Web Traffic:** SquidGuard categorizes web traffic based on URL blacklists, allowing you to apply different filtering policies to different categories of websites. This granular categorization enables more sophisticated content filtering rules, allowing for tailored filtering policies.
        *   **Log Web Activity (Enhanced Logging):** SquidGuard enhances Squid's logging capabilities by providing more detailed logging of web access activity, including website categories, URLs accessed, and filtering actions taken. These enhanced logs are valuable for monitoring user web activity, security auditing, and identifying policy violations. Enhanced logging provides valuable web activity insights.

3.  **Lightsquid (lightsquid):** - Web Traffic Reporting and Analysis Tool for Squid
    *   **Function:** Provides web-based reporting and analysis tools specifically designed to work with Squid proxy logs. Lightsquid processes Squid access logs and generates visual reports and statistics on web traffic, providing valuable insights into web usage patterns.
    *   **Purpose:**
        *   **Monitor Web Activity:** Lightsquid collects and analyzes data from Squid access logs to provide insights into user web browsing activity, including websites visited, access times, bandwidth usage, and top users/websites. Web activity monitoring and analysis are provided.
        *   **Generate Detailed Reports:** Lightsquid generates graphical and tabular reports on web traffic, presenting web usage statistics in a user-friendly and easily understandable format. These reports can include top websites visited, bandwidth usage by user/department, website category statistics, and more. Detailed web traffic reports are generated.
        *   **Detect Web Access Issues:** Lightsquid reports can help identify potential performance bottlenecks related to web access, detect unusual web traffic patterns, and monitor for policy violations or security incidents related to web browsing. Lightsquid reports are valuable for network administrators and security personnel to monitor web usage, identify trends, and troubleshoot web access issues. Web access issues and trends can be identified through reporting.

## 5. Blocking Access to a Specific Website (Facebook Example)

This section demonstrates how to block access to a specific website (Facebook.com in this example) for users in the LAN zone using pfSense firewall rules and Aliases. This method uses a simple firewall rule-based blocking approach, without relying on the more advanced content filtering capabilities of Squid and SquidGuard (demonstrated in previous sections).  This is a basic website blocking example using firewall rules.

**Create an Alias for the Website to Block:**

**Navigation:** **Firewall > Aliases > Add**

**Alias Configuration:** Create a new Alias to represent the website to be blocked. Aliases improve rule manageability.

*   **Name:** `BlockedWebsite` (or any descriptive name you choose, e.g., `FacebookBlock`) -  A descriptive name helps identify the purpose of the Alias. Use descriptive Alias names for clarity.
*   **Type:** `URL Table (easylist + urlhaus)` - Select "URL Table" as the Alias type. This type allows you to create an Alias based on a list of URLs or domain names.  The "(easylist + urlhaus)" option refers to pre-defined URL lists that can be used for blocking ads or malware domains, but for this task, we will use a custom URL. Select URL Table Alias type for website blocking.
*   **URL:** `Facebook.com` - Enter the domain name of the website you want to block: `Facebook.com`. You can add multiple websites to this Alias if needed, listing each domain name on a new line. Add the domain name to block to the URL list.
*   **Description:** `Block access to Facebook` - Add a description to the Alias to document its purpose.  Descriptions are helpful for rule and Alias management and for understanding the configuration later. Add descriptions for documentation.
*   **Save:** Click "Save" to create the Alias. Save the Alias to create it.

![image](https://github.com/user-attachments/assets/4a2bdd19-5345-4ba4-92b3-9de2f8087b61)

**Rationale for Using URL Table Alias:**  Using a "URL Table" Alias allows you to easily block access to websites based on their domain names or URLs. This approach is simpler for basic website blocking compared to setting up Squid and SquidGuard for content filtering, and it directly uses pfSense firewall rules for blocking. URL Table Aliases simplify website blocking rules.

Creating an Alias like this allows us to block `facebook.com`. You can add other websites to this Alias if you want to block multiple websites with the same rule. Now, create a firewall rule to insert the Alias and block Facebook access for the LAN network.  Multiple websites can be blocked by adding them to the Alias.

**Navigation:** Navigate to **Firewall > Rules > LAN**.

**Adding Firewall Rule:** Click **"+ Add"** to create a new Firewall Rule.

**Firewall Rule Configuration:** Create a firewall rule on the LAN interface to block access to the website defined in the `BlockedWebsite` Alias for traffic originating from the LAN zone.  Firewall rules are used to enforce blocking.

![image](https://github.com/user-attachments/assets/26ac9506-03ac-48b3-af61-7328e0fb4ea5)

**Firewall Rule Settings Explanation:**

*   **Action:** `Block` - Set the Action to "Block". This rule will explicitly *deny* traffic that matches its criteria. Explicit block action is used to deny access.
*   **Interface:** `LAN` - Select "LAN" as the Interface. This rule will be applied to traffic originating from the LAN zone. Rule applies to LAN interface.
*   **Protocol:** `TCP` - Set the Protocol to "TCP". Web traffic (HTTP/HTTPS) primarily uses TCP. Rule targets TCP protocol.
*   **Source:** `LAN net` - Set the "Source" to "LAN net," representing the LAN network subnet.  This rule will apply to traffic originating from any IP address within the LAN subnet. Rule source is LAN network.
*   **Destination:** Set "Destination" to `Alias` and enter the name of the alias created earlier: `BlockedWebsite`. This specifies that the destination of the traffic should match the `BlockedWebsite` Alias, which contains the domain name `facebook.com`.
    *   **Rationale:** By setting the Destination to the `BlockedWebsite` Alias, the firewall rule will specifically target traffic destined for `facebook.com` (and any other websites added to this Alias). Rule destination is the BlockedWebsite Alias.
*   **Destination Port Range:** Set "Destination Port Range" to `HTTP` and `HTTPS`. This restricts the blocking rule to only apply to web traffic on ports 80 (HTTP) and 443 (HTTPS).
    *   **Rationale:** Limiting the port range to HTTP and HTTPS ensures that only web traffic destined for Facebook is blocked. Other types of traffic to Facebook's IP addresses (if any) on different ports will not be affected by this rule. Rule targets HTTP and HTTPS ports for web traffic blocking.

**Save the Firewall Rule:** Click "Save" to create the firewall rule. Save the rule to create it.

![image](https://github.com/user-attachments/assets/cefed564-5010-4b38-a932-f42a85e781eb)

**Testing Website Blocking:**

Facebook will now be blocked from access for devices on the LAN network. Testing verifies the rule effectiveness.

![image](https://github.com/user-attachments/assets/b96ce0d1-fd3c-4e82-b6f1-9f8650104691)

**Testing Procedure:**

1.  **Client Machine (LAN Zone):** Use a client machine connected to the LAN network (e.g., a workstation with an IP address in the 192.168.20.0/24 range). Use a LAN client machine for testing.
2.  **Access Blocked Website:** Open a web browser on the client machine and attempt to access `www.facebook.com`. Attempt to access the blocked website.
3.  **Verify Blocking:**  Access to Facebook should be blocked. The web browser should display an error message indicating that the website cannot be reached or that the connection was refused.  This confirms that the firewall rule is successfully blocking access to Facebook for LAN clients. Verify that website access is blocked as expected.

The same process can be done for other websites to block access to multiple websites or to create rules to only *allow* access to a specific list of websites (whitelisting) by adjusting the "Action" of the firewall rule and modifying the Alias accordingly.  The same process can be used for blocking or whitelisting other websites.

## 6. Limiting Internet Access Time with Schedules

This section demonstrates how to use Schedules in pfSense to limit internet access to specific time periods, using YouTube access as an example. Schedules are a powerful feature in pfSense for implementing time-based access control policies, enabling time-based access control policies.

![image](https://github.com/user-attachments/assets/8fce32b8-286b-49e6-8625-78c6c5fad57e)

**Scenario:** Here, we will limit YouTube viewing time every day of September, with blocking starting at 9:30 AM and YouTube access being restored at 1:00 PM. This simulates a common scenario where you might want to restrict access to certain websites or services during specific hours, such as blocking non-work-related websites during working hours.  This scenario simulates time-based website access restriction.

**Create a Schedule:**

**Navigation:** Navigate to **Firewall > Schedules > Add**

**Schedule Configuration:** Create a new Schedule to define the time period for blocking YouTube access. Schedules define time-based access control.

![image](https://github.com/user-attachments/assets/eb342f4d-56cf-482f-b65b-b0fbc184db9a)

**Schedule Settings Explanation:**

*   **Name:** `YouTube_Limit_Schedule` (or any descriptive name) - Choose a descriptive name for the schedule. Use descriptive schedule names for clarity.
*   **Time Range:** Configure the "Time Range" section to define the blocking period. Time range defines the active period of the schedule.
    *   **From:** `9:30 AM` - Set the start time of the blocking period to 9:30 AM. Define schedule start time.
    *   **To:** `1:00 PM` - Set the end time of the blocking period to 1:00 PM. Define schedule end time.
    *   **Days of the Week:** Select all days of the week (Monday through Sunday) to apply this schedule every day. Select days of the week for schedule application.
    *   **Months:** Select "September" to apply this schedule only during the month of September. You can adjust the month or leave it as "Every Month" to apply the schedule year-round. Select months for schedule application.

**Create an Alias for YouTube's Address:**

To block YouTube, we will use a similar Alias approach as in section 5, creating an Alias to represent YouTube's domain name. Aliases are used for website blocking.

![image](https://github.com/user-attachments/assets/982bacf0-868f-4d13-9260-1346ecf35f1d)

**Alias Configuration:** Create a "URL Table" Alias named `BlockedYouTube` and add `youtube.com` to the "URL" list, similar to the `BlockedWebsite` Alias created for Facebook in section 5. Create URL Table Alias for YouTube.

**Create a Firewall Rule to Block YouTube Access with Schedule:**

**Navigation:** Navigate to **Firewall > Rules > LAN**.

**Adding Firewall Rule:** Click **"+ Add"** to create a new Firewall Rule.

**Firewall Rule Configuration:** Create a firewall rule on the LAN interface to block access to YouTube using the `BlockedYouTube` Alias and apply the `YouTube_Limit_Schedule`. Firewall rules enforce time-based blocking.

![image](https://github.com/user-attachments/assets/9047ae22-c9cd-42af-a43e-87c8b259d1cb)

**Firewall Rule Settings Explanation:**

*   **Action:** `Block` - Set the Action to "Block" to deny access to YouTube during the scheduled time.  Explicit block action is used for time-based blocking.
*   **Interface:** `LAN` - Select "LAN" as the Interface, as this rule applies to LAN clients. Rule applies to LAN interface.
*   **Protocol:** `TCP` - Set the Protocol to "TCP" for web traffic. Rule targets TCP protocol.
*   **Source:** `LAN net` - Set "Source" to "LAN net" to apply this rule to all devices on the LAN network. Rule source is LAN network.
*   **Destination:** Set "Destination" to `Alias` and select the `BlockedYouTube` Alias, targeting YouTube's domain name. Rule destination is BlockedYouTube Alias.
*   **Destination Port Range:** Set "Destination Port Range" to `HTTP,HTTPS` to block web access to YouTube. Rule targets HTTP and HTTPS ports.

**Apply the Schedule to the Firewall Rule:**

**Advanced Options:** Scroll down to the "Advanced Options" section of the firewall rule configuration.

Select the Schedule: In the "Advanced Options" section, find the "Schedule" dropdown menu and select the `YouTube_Limit_Schedule` that you created earlier.  Schedules are applied in the Advanced Options of firewall rules.

![image](https://github.com/user-attachments/assets/5ac22414-b9eb-4f6c-8515-d1377ce9c082)

**Rationale for Using Schedules:** By applying the `YouTube_Limit_Schedule` to the firewall rule, the rule will only be active during the times defined in the schedule (every day of September, from 9:30 AM to 1:00 PM). Outside of this scheduled time range, the firewall rule will be inactive, and YouTube access will be allowed (unless blocked by other firewall rules). Schedules activate rules only during defined timeframes.

Set Destination to the Alias name created previously (`BlockedYouTube`). No changes needed here.

![image](https://github.com/user-attachments/assets/b744d4cd-0d99-4599-bd7d-e9c19c2616cc)

**Save the Firewall Rule:** Click "Save" to create the firewall rule with the schedule applied. Save the rule to create it with schedule applied.

YouTube will now be blocked from access for LAN clients during the specified schedule (9:30 AM to 1:00 PM every day in September).  Outside of these hours, YouTube access will be allowed (unless other blocking rules are in place). Time-based YouTube blocking is now configured.

![image](https://github.com/user-attachments/assets/b96ce0d1-fd3c-4e82-b6f1-9f8650104691)

**Schedules in pfSense** are a versatile tool used to define specific time ranges, enabling you to apply policies and rules dynamically based on time.  Schedules can be used for various purposes beyond just limiting website access, including: Schedules are versatile for time-based policies.

*   **Limit Internet Access by Time:** Implement time-based internet access policies, allowing or blocking internet access for specific users, departments, or network segments during certain times of the day or week. This can be used to restrict internet access outside of working hours, for example. Time-based internet access control can be implemented.
*   **Time-Based Bandwidth Control (QoS):** Apply different Quality of Service (QoS) policies during different time frames. For example, you can prioritize bandwidth for video conferencing applications during working hours and reduce bandwidth limits for less critical traffic during peak usage times. Time-based QoS policies can be implemented for bandwidth management.
*   **Automatic VPN On/Off:** Automatically connect VPN connections during working hours and disconnect them after working hours. This can automate VPN management based on a schedule, ensuring secure remote access during specific times. VPN connections can be automated with schedules.
*   **Automatic Blocklist Updates (pfBlockerNG):** Configure pfBlockerNG (a pfSense package for IP and DNSBL blocking) to update ad and malware blocklists automatically during off-peak hours, such as at night, to avoid impacting network performance during the day when users are actively browsing. Automated blocklist updates can be scheduled with pfBlockerNG.
*   **Scheduled Server Startup/Shutdown:** Automatically turn on necessary servers during peak hours and turn them off during off-peak hours to save energy and resources.  You can use Schedules in conjunction with Wake-on-LAN (WOL) or other power management tools to automate server startup and shutdown based on time-based schedules. Server power management can be automated with schedules.

## 7. Traffic Shaping & QoS (Quality of Service): Bandwidth Limiting for Specific Machines

**Purpose:** Prioritize bandwidth for important applications/services, limit bandwidth for less critical applications or users/devices, and ensure a smoother network experience for prioritized tasks, especially during periods of network congestion. QoS helps to manage network bandwidth effectively and ensure that critical applications receive the necessary bandwidth they need to function properly. QoS provides bandwidth prioritization and management for improved network performance.

**Implementation Steps:**

**Create Queues (Limiters):**

**Navigation:** **Firewall > Traffic Shaper > Queues (Limiters in pfSense 2.7.2 and later)**.  In pfSense versions 2.7.2 and later, "Queues" are referred to as "Limiters" in the web interface. The "Queues" menu option might still be present for legacy configurations, but for new configurations, use "Limiters".  In pfSense 2.7.2+, Queues are now called Limiters.

Click **Add** to create a new queue (limiter).  Add limiter to create a new bandwidth limiter.

**Configure Queue (Limiter):**

*   **Name:** Set a descriptive name for the queue (limiter), e.g., `1MB_Download_Limit`, `VoIP_Priority`, `Streaming_Limit`. Choose a name that clearly indicates the purpose of the limiter. Use descriptive limiter names for clarity.
*   **Interface:** Select the network interface to which the limiter should be applied (typically `WAN` for internet bandwidth limiting, or `LAN` for internal network bandwidth management). Select the appropriate interface for limiter application.
*   **Bandwidth:** Define the maximum bandwidth limit for the queue (limiter).  Enter the bandwidth limit in kilobits per second (kbps) or megabits per second (Mbps), e.g., `1 Mbps` or `1000 kbps` for a 1 Mbps limit. Define the bandwidth limit for the limiter.

![image](https://github.com/user-attachments/assets/bfc1702d-a30d-4762-ba3b-60b840c95180)

**Queue (Limiter) Settings Explanation:**

*   **Name:**  `1MP_DOWNLOAD` and `1MB_UPLOAD` (as shown in the example) - Descriptive names are used to identify the download and upload limiters. Use descriptive names for limiters.
*   **Interface:** `WAN` -  The "Interface" is set to "WAN," indicating that these limiters will be applied to traffic going through the WAN interface (internet traffic). Limiter interface is set to WAN for internet traffic limiting.
*   **Bandwidth:** `1 Mbps` -  Both limiters are configured with a bandwidth limit of 1 Mbps (Megabit per second). This means that traffic passing through these limiters will be capped at a maximum bandwidth of 1 Mbps. Bandwidth limit is set to 1 Mbps.

Then click **Save** to create the limiter. Save the limiter to create it.
Here, we will create 2 limiters: `1MB_DOWNLOAD` for download traffic and `1MB_UPLOAD` for upload traffic, each with a bandwidth limit of 1 Mbps.  Two limiters are created: download and upload limiters.

![image](https://github.com/user-attachments/assets/b9d84d87-ca62-4f8d-a215-d6e985bbfa16)

**Create Aliases for Machines to Limit:**

To apply the bandwidth limiters to specific machines, we will create Aliases for their IP addresses, similar to how we created Aliases for departments and websites in previous sections. Aliases are used to target specific machines for bandwidth limiting.

Then go back to **Aliases** (**Firewall > Aliases**) and create an Alias for Traffic Shaping for each machine you want to limit.

![image](https://github.com/user-attachments/assets/67cc917c-a2a4-4752-869a-190e0c8c3e2a)

**Alias Configuration:** Create an Alias of type "Hosts" (or "Network") to group the IP addresses of the machines you want to apply bandwidth limiting to. Create Host Alias for machines to be limited.

**Alias Settings Explanation:**

*   **Name:** `TrafficShaping_Machines` (or any descriptive name) - Choose a name for the Alias to identify the machines being limited. Use descriptive Alias names.
*   **Type:** `Hosts` or `Network(s)` - Select "Hosts" if you are limiting individual machines by IP address, or "Network(s)" if you are limiting a range of IP addresses or a subnet. Select Alias type Host or Network for IP targeting.
*   **Hosts/Network(s):** Enter the IP addresses of the machines you want to limit, one IP address per line if using "Hosts" type, or an IP range/subnet if using "Network(s)" type. Add IP addresses to the Alias list.

**Create Firewall Rule to Apply Limiters:**

Now, create a firewall rule to apply the `1MB_DOWNLOAD` and `1MB_UPLOAD` limiters to traffic originating from the machines defined in the `TrafficShaping_Machines` Alias. Firewall rule applies the limiters to targeted machines.

Test speed before applying the limiter rule to see the baseline bandwidth speed. Baseline speed testing is performed before limiter rule application.

![image](https://github.com/user-attachments/assets/6b4af539-1eb6-440a-8d93-0773e02d405b)

**Testing Baseline Speed:** Before applying the traffic shaping rule, perform a speed test from one of the machines you intend to limit to measure the baseline download and upload speeds. This provides a comparison point to verify that the limiter rule is working correctly after it's applied. Use online speed test websites or tools like `speedtest-cli` to measure bandwidth. Baseline speed tests provide a comparison point for limiter effectiveness.

Create a firewall rule on the LAN interface to apply the limiters. Here, we will apply it to all protocols, set Action to Pass (because we are *allowing* traffic, but with bandwidth limitations applied). Firewall rule allows traffic but applies bandwidth limits.

![image](https://github.com/user-attachments/assets/0bba5894-609f-419e-9dc7-7ed2b1a0c066)

**Firewall Rule Settings Explanation (Traffic Shaping Rule):**

*   **Action:** `Pass` - Set the Action to "Pass" because we are *allowing* traffic from the specified machines, but we are *limiting* their bandwidth using QoS.  The rule allows the traffic to pass through the firewall, but the QoS limiters will then be applied to shape and limit the bandwidth. Pass action allows traffic with QoS limits.
*   **Interface:** `LAN` - Select "LAN" as the Interface, as this rule applies to traffic originating from the LAN zone machines that we want to limit. Rule applies to LAN interface for limiting LAN client traffic.
*   **Protocol:** `any` - Set "Protocol" to "any" to apply the bandwidth limiting to all protocols (TCP, UDP, ICMP, etc.). Bandwidth limiting is typically applied regardless of the protocol used. Rule targets all protocols for bandwidth limiting.
*   **Source:** Set "Source" to `Alias` and select the `TrafficShaping_Machines` Alias. This applies the rule to traffic originating from the IP addresses defined in the `TrafficShaping_Machines` Alias, targeting the specific machines you want to limit. Rule source is TrafficShaping_Machines Alias for targeted machine limiting.

Go to **Advanced Options** section of the firewall rule and scroll down to the bottom. In the "In/Out pipe" section (Traffic Shaper section in newer pfSense versions), set:  Limiters are applied in the Advanced Options of firewall rules.

*   **"In" pipe (Inbound traffic - from WAN to LAN):** Set to `1MB_UPLOAD`.  **Important Note:**  The "In" pipe in a *LAN* firewall rule actually controls the *upload* bandwidth from the LAN client *to* the WAN (internet). It's counterintuitive, but "in" and "out" pipes in firewall rules are relative to the *firewall interface*, not relative to the LAN client. So, "in" pipe on the LAN interface controls *outbound* traffic from the LAN. Here, we are limiting the *upload* speed from the LAN clients to 1 Mbps. "In" pipe on LAN interface controls upload bandwidth.
*   **"Out" pipe (Outbound traffic - from LAN to WAN):** Set to `1MB_DOWNLOAD`. **Important Note:** The "Out" pipe in a *LAN* firewall rule controls the *download* bandwidth from the WAN (internet) *to* the LAN client.  So, "out" pipe on the LAN interface controls *inbound* traffic to the LAN, which is download traffic from the internet perspective. Here, we are limiting the *download* speed to the LAN clients to 1 Mbps. "Out" pipe on LAN interface controls download bandwidth.

Then click **Save** to create the firewall rule with traffic shaping applied. Save the rule to create it with traffic shaping.

After saving the rule, apply the changes. Apply changes to activate the rule.

And restart the speed test from a machine with a limited IP address (defined in the `TrafficShaping_Machines` Alias). Download and upload speeds for the desired PC are now limited to approximately 1 Mbps, as defined in the limiters. We can add more PCs to be bandwidth-limited by adding their IP addresses to the `TrafficShaping_Machines` Alias. Retest speed to verify limiter effectiveness.

![image](https://github.com/user-attachments/assets/6761b98e-1d53-42c1-8fff-861de47c7c51)

**Testing Limited Speed:** After applying the traffic shaping rule, perform another speed test from the same client machine. The download and upload speeds should now be significantly reduced, close to the 1 Mbps limit you configured in the limiters. This verifies that the traffic shaping and QoS rules are working correctly and are effectively limiting the bandwidth for the targeted machines. Verify that bandwidth is limited after rule application.

## 8. Captive Portal: Implementing a Mandatory Login Page for Wi-Fi Access

**Purpose:** Create a Captive Portal on pfSense to implement a mandatory login page for users attempting to access a Wi-Fi network (or any network segment). Captive Portals are commonly used in public Wi-Fi hotspots, guest networks, or corporate guest Wi-Fi to: Captive Portals enforce login for network access.

*   **Require User Authentication:**  Force users to log in with credentials before they can access the internet or network resources, enhancing security and accountability. User authentication is enforced for network access.
*   **Display Terms of Service:** Present users with terms of service or usage policies that they must accept before gaining access. Terms of service can be displayed before access is granted.
*   **Collect User Information (Optional):**  Optionally collect user information like email addresses or names during the login process for marketing or logging purposes. User information collection is optional.
*   **Control Access Duration (Time Limits):**  Limit the duration of internet access for users, especially useful in public hotspots or guest networks. Access duration can be controlled through timeouts.
*   **Redirect to Custom Pages (Branding/Advertising):** Redirect users to custom landing pages after login, which can be used for branding, advertising, or displaying important information. Custom landing pages can be used for branding and information.

**Implementation Steps:**

**Installation:**

**Navigation:** **Services > Captive Portal > Add**

Captive Portal is not installed by default in pfSense.  You may need to install the Captive Portal package first if it's not already installed.  To install packages in pfSense, navigate to **System > Package Manager > Available Packages** and search for "Captive Portal" and install it. Once installed, the "Captive Portal" menu option will appear under the "Services" menu. Captive Portal package installation is required if not already installed.

**Create a Zone:**

**Navigation:** **Services > Captive Portal > Add** (after installation)

Click **Add** to create a new Captive Portal zone. Each Captive Portal instance in pfSense is called a "Zone." You can create multiple zones for different network interfaces or different access policies. Create a Captive Portal Zone to configure a new instance.

![image](https://github.com/user-attachments/assets/ac971ddd-cd1d-4d2c-97ec-4282645f7b15)

**Captive Portal Zone Configuration - Basic Settings:**

**Enable Captive Portal:** Check the "Enable Captive Portal" checkbox to activate the Captive Portal zone. Enable Captive Portal to activate the zone.

**Interface Selection:** Choose the network interface to which the Captive Portal should be applied. Here, we will choose the `LAN` network, meaning the Captive Portal will be active for users connecting to the LAN interface (e.g., Wi-Fi users connected to an access point on the LAN). Select LAN interface for Captive Portal application.

![image](https://github.com/user-attachments/assets/f648d6bc-8aca-402b-9bf2-0bd3d12444d9)

**Captive Portal Zone Settings Explanation (Basic):**

*   **Enable Captive Portal:**  Enables or disables the Captive Portal functionality for this zone.  The Captive Portal will only be active if this checkbox is checked. Enable Captive Portal checkbox activates the feature.
*   **Interface:** `LAN` - Selects the LAN interface as the network segment where the Captive Portal will be active.  When users connect to the LAN network (e.g., via Wi-Fi), they will be redirected to the Captive Portal login page.  LAN interface is selected for Captive Portal application.
*   **Zone name:**  `captiveportalzone0` (default or you can customize) -  Assigns a name to the Captive Portal zone for identification and management. Zone name identifies the Captive Portal instance.
*   **Maximum concurrent connections:** (Set a limit if needed) -  Allows you to limit the maximum number of concurrent users who can be authenticated through the Captive Portal simultaneously. This can be used to control resource usage or limit the number of guest users. Concurrent connection limit can be set.
*   **Idle timeout:** (Set a timeout if needed) -  Defines the idle timeout period in seconds. If a user is idle for this duration (no network activity), their Captive Portal session will be automatically disconnected, and they will need to re-authenticate upon next access attempt. Idle timeout disconnects inactive sessions.
*   **Hard timeout:** (Set a timeout if needed) - Defines the maximum session timeout in seconds.  Regardless of activity, a user's Captive Portal session will be automatically disconnected after this duration, and they will need to re-authenticate. Hard timeout disconnects sessions after a fixed duration.
*   **Authentication method:**  This setting determines how users will authenticate through the Captive Portal. We will configure this to "Use an Authentication backend" in the next step for user-based authentication. Authentication method is set to Authentication Backend for user-based login.

**Customize Theme (Optional):**

Customize one of the two default themes, or upload a custom theme for the Captive Portal login page. Custom themes allow for branding and customization.

Templates for custom Captive Portal themes can be found on GitHub and other online resources. Here, we will use a sample template from GitHub for demonstration purposes.  Customizing the theme allows you to brand the Captive Portal login page with your organization's logo, colors, and messaging, providing a more professional and branded user experience. Custom themes enhance user experience and branding.

![image](https://github.com/user-attachments/assets/61be41d7-bd6b-4ffb-ade3-9de0ce5f40ce)

**Authentication Method Configuration:**

**Authentication Method:** Customize security by selecting the authentication method for the Captive Portal. Here, we will choose "Use an Authentication backend" for user-based authentication. Authentication Backend is selected for user-based login.

![image](https://github.com/user-attachments/assets/b8c7410a-675f-4575-acef-3f4bf8601c6f)

**Authentication Settings Explanation:**

*   **Authentication method:** `Use an Authentication backend` -  Selects "Use an Authentication backend" as the authentication method. This option allows you to use pfSense's built-in User Manager or external authentication backends (like RADIUS or LDAP servers) to manage user accounts and authentication.
    *   **Rationale:** "Use an Authentication backend" provides a secure and manageable way to authenticate Captive Portal users, allowing you to control user access, manage user accounts, and potentially integrate with existing user directories. Authentication Backend enables secure user account management and integration.

Then click **Save** to save the Captive Portal zone configuration. Save Captive Portal zone configuration after setting basic settings.

![image](https://github.com/user-attachments/assets/756d0b66-b13c-4184-98ca-e73999a370f0)

**Create User Accounts for Captive Portal Authentication:**

To use the "Authentication backend" method, you need to create user accounts in pfSense's User Manager. These user accounts will be used by users to log in to the Captive Portal. User accounts are needed for Authentication Backend method.

**Navigation:** **System > User Manager > Users > Add**

Create users in the User Manager section and save.  Remember that Captive Portal usernames typically do not allow spaces. In the image, a username with a space was accidentally entered, which might cause issues. Usernames should be alphanumeric and without spaces for Captive Portal authentication. User accounts are created in User Manager for Captive Portal login.

![image](https://github.com/user-attachments/assets/3c5fe916-f035-42d6-9627-315b8a4d1d5f)

**User Configuration Explanation:**

*   **Username:**  `cp_user1`, `cp_user2`, etc. - Create usernames for Captive Portal users. Ensure usernames are alphanumeric and do not contain spaces. Usernames should be alphanumeric without spaces.
*   **Password:** Set strong passwords for each user account. Use strong passwords for user accounts.
*   **Full name:** (Optional) Enter the full name of the user for identification purposes. Full name is optional for user identification.
*   **Expiration date:** (Optional) Set an expiration date for the user account if you want to limit the account validity period. Account expiration date is optional for time-limited accounts.

**Configure User Privileges for Captive Portal Access:**

By default, newly created users in pfSense do not have Captive Portal privileges. You need to explicitly grant Captive Portal access privileges to the user accounts you created. Captive Portal privileges must be explicitly granted to users.

Go to the **Action** section of the user account (edit user) to edit user privileges and assign Captive Portal access. Edit user privileges to assign Captive Portal access.

Click "Add privileges" and select the following options (as shown in the image) to grant Captive Portal access privileges to the user account:

![image](https://github.com/user-attachments/assets/22df3d79-1f01-4245-a791-1b8218dec5b2)

**User Privileges Settings Explanation:**

*   **Available Privileges:** In the "Available Privileges" list, search for and select the following privileges: Grant these specific privileges for Captive Portal access.
    *   `user-portal: All User Portal access` - Grants general access to the User Portal (Captive Portal login page and user self-service portal if enabled). Grants general User Portal access privilege.
    *   `user-portal-auth: Captive Portal Authentication` -  This is the *essential* privilege for Captive Portal authentication. It allows the user to authenticate through the Captive Portal login page using their username and password. Grants essential Captive Portal Authentication privilege.
    *   `webcfg: User - System User` -  This privilege is generally needed for basic user access and might be required by the Captive Portal system for user management. Grants general System User privilege.
    *   **(Optional Privileges):** You can explore other user portal-related privileges to customize user access to the Captive Portal and user self-service portal features further, depending on your requirements. Explore optional privileges for further customization.

After selecting the necessary privileges, click "Save" to apply the changes to the user account. Save user privilege changes to apply them.

![image](https://github.com/user-attachments/assets/22df3d79-1f01-4245-a791-1b8218dec5b2)

**Testing Captive Portal Authentication:**

After configuring the Captive Portal zone, creating user accounts, and assigning Captive Portal privileges, test the Captive Portal authentication process from a client machine connected to the LAN network (or the network interface where you enabled the Captive Portal). Test Captive Portal authentication after configuration.

After that, every time a user from a LAN PC wants to access a website, they will be automatically redirected to the Captive Portal login page and will have to enter a valid username and password created in pfSense's User Manager to gain internet access. Users are redirected to Captive Portal login page for authentication.

![image](https://github.com/user-attachments/assets/f9c7db6b-5b8e-424d-8c06-2dbb09137eb4)

**Testing Procedure:**

1.  **Client Machine (LAN Zone):** Connect a client machine (e.g., a laptop or mobile device) to the LAN network (or the Wi-Fi network associated with the LAN interface if you are using a wireless access point on the LAN). Use a LAN client machine for testing.
2.  **Open Web Browser:** Open a web browser on the client machine and attempt to access any website (e.g., `www.google.com`). Attempt to access a website from the client machine.
3.  **Captive Portal Redirection:** The web browser should automatically redirect to the Captive Portal login page.  Instead of the website you tried to access, you should see the Captive Portal login page displayed in your browser. Verify Captive Portal redirection occurs.
4.  **Login with User Credentials:** Enter the username and password of a user account you created in pfSense User Manager that has Captive Portal privileges (e.g., `cp_user1` and its password). Login with valid user credentials.
5.  **Successful Authentication:** After successful login, you should be redirected to the originally requested website (e.g., `www.google.com`) or a "success" page defined in the Captive Portal settings. You should now have internet access through the Captive Portal. Verify successful authentication and internet access after login.
6.  **Test without Login (Before Authentication):** Before logging in to the Captive Portal, verify that internet access is blocked.  Try to browse to websites or ping external hosts. Access should be blocked until you successfully authenticate through the Captive Portal login page. Verify internet access is blocked before successful Captive Portal login.

## 9. Blocking File Downloads by File Format using SquidGuard (Content Filtering)

This section demonstrates how to use SquidGuard, the advanced content filtering package for Squid, to block file downloads based on file extensions (file formats). In this example, we will block the download of `.exe` files (executable files), a common security measure to prevent users from downloading potentially malicious executables. SquidGuard is used for file download blocking based on file extensions.

Here, we will block `.exe` files like this (using SquidGuard).

![image](https://github.com/user-attachments/assets/02330c4f-4616-4988-9598-604331179c39)

**Navigation:** Navigate to **Services > SquidGuard Proxy Filter > Target Categories**.

Go to the **Target Categories** section in SquidGuard configuration. Target Categories define blacklists and whitelists in SquidGuard.

![image](https://github.com/user-attachments/assets/990a3e6c-d5df-4c66-8da0-1605f93645be)

**Adding Blacklist Category for Executable Files:**

Click **Add** to create a new Target Category for blocking `.exe` files.  In SquidGuard terminology, "Target Categories" are often used to define blacklists or whitelists of websites or content types for filtering. Add Target Category to create blacklist for EXE files.

**Category Configuration:** Configure a new Target Category to blacklist `.exe` file downloads. Configure Target Category to blacklist EXE downloads.

![image](https://github.com/user-attachments/assets/7956befb-b288-402c-bebc-0220c5c24c17)

**Target Category Settings Explanation:**

*   **Name:** `Blocked_EXE_Files` (or any descriptive name) - Choose a name for the Target Category that clearly indicates its purpose (blocking EXE files). Use descriptive Target Category names for clarity.
*   **Blacklist - "File extension" Section:**  Scroll down to the "Blacklist" section within the Target Category configuration.  Find the "File extension" subsection. Configure File extension blacklist in Blacklist section.
    *   **File extension:** `.exe` - Enter the file extension you want to block: `.exe`.  This tells SquidGuard to block downloads of files with the `.exe` extension.  You can add multiple file extensions to block different file types. Add .exe file extension to block EXE downloads.
    *   **Rationale:** By specifying `.exe` as a blocked file extension, SquidGuard will inspect downloaded files and block any file that has the `.exe` extension in its URL or Content-Disposition header, preventing users from downloading executable files through the proxy. SquidGuard blocks EXE file downloads based on extension filtering.

Add a custom "lỗi rồi :D" (error message :D) redirect URL (optional, for demonstration purposes) and save.  You can customize the "Redirect" settings in the Target Category to display a custom error page or redirect users to a specific URL when they attempt to download blocked file types. In this example, a simple text message "lỗi rồi :D" (error :D) is used as the redirect URL.  Custom redirect URL can be set for blocked file downloads.

![image](https://github.com/user-attachments/assets/a0606764-d229-4820-b7a7-62ef5fa35962)

**Configure Common ACL (Access Control List) to Apply Blacklist:**

To activate the `.exe` file download blocking, you need to configure the "Common ACL" (Access Control List) in SquidGuard to apply the `Blocked_EXE_Files` Target Category and set the action to "Deny". The Common ACL defines the default filtering policy that applies to all traffic passing through the Squid proxy, unless overridden by Group ACLs (as demonstrated in section 2). Common ACL applies blacklist to all proxy traffic.

In the **Common ACL** section (Services > SquidGuard Proxy Filter > Common ACL), adjust the newly created Target Category (`Blocked_EXE_Files`), ensuring it is set to **Deny**.  Set Blocked_EXE_Files Target Category to Deny in Common ACL.

**Common ACL Settings Explanation:**

*   **Common ACL:**  The "Common ACL" section defines the default filtering policy for SquidGuard.  Rules defined in the Common ACL apply to all proxy traffic unless overridden by Group ACLs. Common ACL defines default filtering policy.
*   **`Blocked_EXE_Files` Category:**  Find the `Blocked_EXE_Files` Target Category you created in the Common ACL table. Locate Blocked_EXE_Files Target Category in Common ACL.
*   **Action for `Blocked_EXE_Files`:**  Set the "Action" for the `Blocked_EXE_Files` Category to **"Deny"**. This tells SquidGuard to *block* access to any content that falls under the `Blocked_EXE_Files` Category (which we defined as `.exe` file downloads). Set Action for Blocked_EXE_Files Category to Deny to block EXE downloads.


![image](https://github.com/user-attachments/assets/d69f803d-2cfe-429a-97ca-04abbb509cb6)


Then apply the changes by clicking "Apply" in the SquidGuard General Settings page. Apply changes in SquidGuard General Settings page to activate.

![image](https://github.com/user-attachments/assets/d1b307c5-b136-46bc-832c-58c09657bebc)



Go back to a website (from a client machine using the Squid proxy) and attempt to download an `.exe` file again. Retest EXE file download from a client machine using Squid proxy.

**Testing File Download Blocking:**

After applying the SquidGuard configuration changes, test the file download blocking from a client machine on the LAN that is configured to use the Squid proxy. Test file download blocking after SquidGuard configuration.

![image](https://github.com/user-attachments/assets/06fcafc8-7164-4db9-80cc-f4d0b22ed57c)

![image](https://github.com/user-attachments/assets/d8e82b14-c14d-46c7-9a57-b8b790467f0e)

**Testing Procedure:**

1.  **Client Machine (LAN Zone, Using Squid Proxy):** Use a client machine on the LAN network that is configured to use the pfSense Squid proxy (as configured in section 2). Use a LAN client machine using Squid proxy for testing.
2.  **Attempt to Download .exe File:**  Browse to a website that offers `.exe` file downloads (e.g., a software download site or a test file download site). Click on a link to download an `.exe` file. Attempt to download an EXE file from a website.
3.  **Verify Blocking:**  File download should be blocked by SquidGuard. Instead of downloading the `.exe` file, the browser should display the custom error message you configured in the `Blocked_EXE_Files` Target Category (e.g., "lỗi rồi :D") or a default SquidGuard block page if you did not configure a custom redirect.  This confirms that SquidGuard is successfully blocking `.exe` file downloads based on the file extension filtering rule you created. Verify that EXE file download is blocked and custom error message is displayed.

</details>
