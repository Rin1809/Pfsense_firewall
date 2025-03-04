![image](https://github.com/user-attachments/assets/4af9bb86-d9a5-4573-bfaf-45e0e8fc4d09)# PfSense Firewall Configuration: Realistic Lab Simulation 1

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

# PfSense Firewall Configuration: Realistic Lab Simulation 2


**Purpose:** This report outlines the configuration of a pfSense system, including information about rules, etc.

**Set Up:** The pfSense system is running version 2.7.2-RELEASE (amd64). The network interface configuration is as follows:

![image](https://github.com/user-attachments/assets/eb56b5a1-154e-4785-a5db-29a5b87c6c1a)


| Interface | Interface Name | IP Address         | Description                                                                                                                                 |
| --------- | -------------- | ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- |
| WAN       | em0            | 192.168.19.10/24   | **WAN (Wide Area Network):** Interface em0 is assigned to the WAN and has IP address 192.168.19.10/24. This interface connects pfSense to the internet or external networks. |
| LAN       | em1            | 192.168.20.10/24   | **LAN (Local Area Network):** Interface em1 is assigned to the LAN and has IP address 192.168.20.10/24. This interface connects pfSense to the internal network, where devices like computers, printers, etc., are connected. |
| DMZ       | em2 (opt1)     | 192.168.30.10/24   | **DMZ (Demilitarized Zone):** Interface em2 (opt1) is assigned to the DMZ and has IP address 192.168.30.10/24. This is a separate network zone, located between the LAN and WAN, typically used to place public servers (web servers, mail servers, etc.) to enhance security for the LAN. |
| DTB       | em3 (OTP2)     | 192.168.40.10/24   | **DTB (Data Zone):** Interface em3 (OTP2) is assigned to the DTB and has IP address 192.168.40.10/24. This zone is for database servers or sensitive data.                                            |


The current network configuration of pfSense demonstrates the system being used to separate the LAN and DMZ networks, creating an additional layer of security for the internal network.  The use of 3 separate interfaces (WAN, LAN, DMZ) allows for flexible rule application and tight control of network traffic between network zones.

**1. Initial Check:**

The default rules for LAN and DMZ are different.

![image](https://github.com/user-attachments/assets/96b24fc5-d159-49fa-a576-75dd359709bb)


By default, the LAN zone has a default rule allowing everything, so it can access the internet.

![image](https://github.com/user-attachments/assets/5b036c25-4654-4ed2-98d5-94847b2b0d58)


For the DMZ zone, there are no rules, so by default, it cannot access the internet.

![image](https://github.com/user-attachments/assets/46fbf21c-a635-44dd-a7c7-7ba67925e732)

**1. Allowing DMZ to Access the Internet**


This rule applies to all IP protocols (IPv4), all packets originating from subnets within the DMZ and destined for any destination. (Simply put, the DMZ zone can now access the internet).
![image](https://github.com/user-attachments/assets/160d4ba0-91e5-4438-8f9c-f1fa0e01d707)

Save and test:

![image](https://github.com/user-attachments/assets/87478476-3acd-474d-820b-c98f931f21df)


**Caution:**  Because the Destination is set to "Any" on both cards, this rule will apply to all destination addresses, both inside and outside the network, including ping. If the rule is intended for specific traffic, opening it to all destinations could allow attackers to reach any device on the network. Therefore, we should only allow necessary ports like 443 for HTTPS, 80 for HTTP, and 22 for SSH.

![image](https://github.com/user-attachments/assets/cedc79f2-8a14-47ff-82d7-3b1378f32f29)


**2. Modifying Rules to Block Ping and Allow Only Ports 22, 80, 443**

**Method 1: Modifying the Protocol and Destination Port Range**

Change the Protocol to TCP and the Destination Port Range to the desired port.

![image](https://github.com/user-attachments/assets/a4607017-5ff5-420b-b3b5-404ceb7ca4fc)


Do the same for the remaining ports.

**Method 2: Using Aliases**

Create an Alias and add the desired ports.

![image](https://github.com/user-attachments/assets/d0f24f56-e9e1-4793-b211-80dc50f5246f)

Go back to the Rule and modify it to:

![image](https://github.com/user-attachments/assets/49f71959-f234-45e5-a746-7fd159892914)


**Benefit:** Convenient, easy to manage, better than Method 1.

However, if we only add ports 80 or 443, while we can access the internet in a basic sense, we can only access websites using their IP addresses directly. We cannot use domain names because domain name resolution to IP addresses is not possible, leading to inability to access the internet using URLs.

**Solution:** Add port 53 (DNS) to the aliases to enable domain name resolution.

![image](https://github.com/user-attachments/assets/45875170-a04a-4db2-9df1-218b12c020af)



Following this approach, we can customize for other services as needed:

*   **Email:** Sending and receiving emails using ports 25 (SMTP), 110 (POP3), 143 (IMAP), etc.
*   **FTP:** File transfer using ports 21 (FTP control), 20 (FTP data), etc.
*   **VPN:** VPN connections often use ports like 1723 (PPTP), 4500 (IPsec), 1194 (OpenVPN), etc.
*   **Remote Desktop:** Remote computer access typically uses port 3389 (RDP), etc.
*   **Online Games:** Online games often use different ports depending on the game.

**3. Creating a Rule to Block Ping, Blocking All ICMP Traffic from the Internet to the LAN**

Purpose: To mitigate flood attacks.

To achieve this, we need to create a rule for the LAN zone.

![image](https://github.com/user-attachments/assets/e9af85f9-11ae-44eb-8bfb-fb0a3f29452b)


Set Action to Block (block).
Set Interface to WAN.
Set Protocol to ICMP.

This section is customizable. Here, we will block all ICMP from WAN to LAN.

![image](https://github.com/user-attachments/assets/9e37b3b8-eed0-457b-8c5c-713faca9fabc)

**Benefits of the Rules:**

*   **Enhanced Security:** Blocking ICMP from WAN helps prevent attackers from using ping and traceroute to scan the LAN, looking for active devices and security vulnerabilities.
*   **Scope of Impact:** This rule only blocks ICMP traffic from the Internet to the LAN, not affecting ICMP traffic between other interfaces (LAN, DMZ).
*   **Mitigation of Denial-of-Service (DoS) Attacks:** Some DoS attacks use ICMP flood, sending a large amount of ICMP traffic to the target to overload the system. Primarily to prevent external attackers from using ping and other ICMP tools to scan the LAN, looking for active devices and security vulnerabilities.

**!! However, there is an issue: the DMZ can still ping the LAN.**

If someone gains access to the DMZ zone, they can scan the LAN because the DMZ can still ping the LAN. They can use ping to scan the LAN, looking for active devices and security vulnerabilities.

---> **Solution:** Add an ICMP blocking rule to block ping from DMZ as well.

![image](https://github.com/user-attachments/assets/a59ef7fc-75d1-45b3-aef9-d5c3a54e6f58)


Create a rule on the DMZ interface with the source as DMZ subnet and the destination as LAN subnet to block all ICMP to the LAN.

And then the DMZ will no longer be able to ping the LAN. Enhancing security.

**Benefits:** More secure, less risky.

**Drawbacks:** Difficulty in network troubleshooting, may affect some applications or services that might use ICMP for special functions.

However, overall, the security benefits outweigh the risks.

In addition to blocking ping from WAN to LAN and DMZ to LAN (mentioned earlier), we can also consider blocking ping from the following directions to further enhance network security:

1.  **LAN to WAN:**
    *   **Purpose:**
        *   Prevent external attackers from using ping to scan devices in the LAN.
        *   Reduce the risk of Denial-of-Service (DoS) attacks from outside.
    *   **Note:**
        *   Blocking ping from LAN to WAN may affect some applications or services that need to use ping to check internet connectivity.
        *   If you need to allow some devices in the LAN to ping outwards, create a separate rule allowing ping with restricted conditions.

2.  **DMZ to WAN:**
    *   **Purpose:**
        *   Prevent external attackers from using ping to scan servers in the DMZ.
        *   Reduce the risk of Denial-of-Service (DoS) attacks from outside.
    *   **Note:**
        *   Blocking ping from DMZ to WAN may affect some applications or services that need to use ping to check internet connectivity.
        *   If you need to allow some servers in the DMZ to ping outwards, create a separate rule allowing ping with restricted conditions.

3.  **LAN to DMZ (if needed):**
    *   **Purpose:**
        *   Prevent scanning and attacks from the LAN network to the DMZ. Enhance isolation between LAN and DMZ.
    *   **Note:**
        *   Blocking ping from LAN to DMZ may affect some applications or services that need to use ping to connect to servers in the DMZ.
        *   Careful consideration is needed before applying, as it may cause more hindrance than blocking ping in other directions.

| From | To  | Purpose                                     | Recommendation |
| ---- | --- | ------------------------------------------- | -------------- |
| WAN  | LAN | Prevent external attacks                      | Should Block   |
| DMZ  | LAN | Prevent attacks from DMZ, isolate DMZ        | Should Block   |
| LAN  | WAN | Prevent scanning, external attacks          | Consider       |
| DMZ  | WAN | Prevent scanning, external attacks          | Consider       |
| LAN  | DMZ | Isolate LAN from DMZ                        | Consider Carefully |

**4. Squid, SquidGuard (squidGuard), Lightsquid (lightsquid).**

Downloading via command or interface failed :((

![image](https://github.com/user-attachments/assets/2c1551ac-c01b-4050-9a28-304f8e244882)

But simply put, I can explain these three packages as follows:

On pfSense, there are 3 packages related to Squid, each with different functions and purposes:

1.  **Squid (squid):**
    *   **Function:** Provides basic proxy server service (HTTP/HTTPS proxy).
    *   **Purpose:**
        *   **Cache web content:** Squid stores (caches) web pages and other web content that users have accessed. When users revisit the same webpage, Squid will return the content from the cache, speeding up web access and reducing bandwidth consumption.
        *   **Control web access:** Squid can be configured to block access to specific websites, filter web content, limit bandwidth, etc.
        *   **User Authentication:** Squid can require users to authenticate (username/password) before accessing the Internet.

2.  **SquidGuard (squidGuard):**
    *   **Function:** Provides advanced web content filtering features for Squid.
    *   **Purpose:**
        *   **Block inappropriate websites:** SquidGuard can block access to websites containing adult content, violence, gambling, etc.
        *   **Categorize web traffic:** SquidGuard can categorize web traffic into different groups (e.g., social media, news, entertainment, etc.) and apply different policies to each group (e.g., bandwidth limiting, blocking access during working hours, etc.).
        *   **Log web activity:** SquidGuard can record detailed logs of user web access activity.

3.  **Lightsquid (lightsquid):**
    *   **Function:** Provides web traffic reporting and analysis tools for Squid.
    *   **Purpose:**
        *   **Monitor web activity:** Lightsquid collects information about user web access activity, such as websites accessed, access time, bandwidth consumption, etc.
        *   **Generate detailed reports:** Lightsquid generates visual reports on web traffic, helping you better understand how users are using the Internet.
        *   **Detect web access issues:** Lightsquid can help you detect performance or security issues related to web access.

**5. Blocking Access to a Specific Website**

**Create an Alias for the website to block:**

**Firewall > Aliases > Add**

*   **Name:** BlockedWebsite (or any name)
*   **Type:** URL Table (easylist + urlhaus)
*   **URL:** Facebook.com
*   **Description:** Block access to Facebook
*   **Save**
![image](https://github.com/user-attachments/assets/4a2bdd19-5345-4ba4-92b3-9de2f8087b61)

Creating an Alias like this allows us to block facebook.com (add other websites if desired). Now, create a rule to insert the alias and block Facebook access for the LAN network.

![image](https://github.com/user-attachments/assets/26ac9506-03ac-48b3-af61-7328e0fb4ea5)



Set Action to Block, meaning block access.

*   **Source:** From LAN subnet.
*   **Destination:** Set to Alias and enter the name of the alias created earlier.
*   **Destination Port Range:** Set to other and choose the port alias created earlier.
*   **Save**

![image](https://github.com/user-attachments/assets/cefed564-5010-4b38-a932-f42a85e781eb)

Facebook will now be blocked from access.

![image](https://github.com/user-attachments/assets/b96ce0d1-fd3c-4e82-b6f1-9f8650104691)


The same can be done for other websites to block or only allow access to a single website by using Aliases.

**6. Limiting Internet Access Time with Schedules**

![image](https://github.com/user-attachments/assets/8fce32b8-286b-49e6-8625-78c6c5fad57e)

Here, we will limit YouTube viewing time every day of September, with blocking starting at 9:30 AM and YouTube access being restored at 1:00 PM.
![image](https://github.com/user-attachments/assets/eb342f4d-56cf-482f-b65b-b0fbc184db9a)


Create an alias to contain YouTube's address.

![image](https://github.com/user-attachments/assets/982bacf0-868f-4d13-9260-1346ecf35f1d)


Then create a rule to apply these restrictions to YouTube.


![image](https://github.com/user-attachments/assets/9047ae22-c9cd-42af-a43e-87c8b259d1cb)


Set Action to Block to apply the Schedule.

![image](https://github.com/user-attachments/assets/5ac22414-b9eb-4f6c-8515-d1377ce9c082)


Set Destination to the Alias name created previously.

![image](https://github.com/user-attachments/assets/b744d4cd-0d99-4599-bd7d-e9c19c2616cc)




In the Advanced Options section, select the Schedule we created earlier to limit YouTube access time. Save and done, YouTube viewing time can now be limited.


**Schedules in pfSense** are used to define a specific time range, helping you apply policies and rules flexibly over time.

*   **Limit Internet Access by Time:** As done with blocking YouTube, we can allow internet access only during certain time frames.
*   **Time-Based Bandwidth Control:** Apply different QoS policies in different time frames. For example, prioritize bandwidth for video call applications during working hours.
*   **Automatic VPN On/Off:** Automatically connect VPN during working hours and disconnect after working hours.
*   **Automatic Blocklist Updates:** pfBlockerNG configuration can be added to update ad/malware blocklists at night, avoiding performance impact during the day.
*   **Scheduled Server Startup/Shutdown:** Automatically turn on necessary servers during peak hours and turn them off during off-peak hours to save energy.




**7. Traffic Shaping & QoS:**

**Purpose:** Prioritize bandwidth for important applications/services, limit bandwidth for applications/users/devices, ensure smooth network experience for prioritized tasks.

**Implementation Steps:**

**Create Queues:**

**Firewall > Traffic Shaper > Queues.**

Click **Add** to create a new queue.

**Configure Queue:**

*   **Name:** Set a name for the queue, e.g., VoIP_Priority, Streaming_Limit.
*   **Interface:** Select the network interface to apply to (WAN, LAN).
*   **Bandwidth:** Define the maximum bandwidth limit for the queue (e.g., 1Mbps).
![image](https://github.com/user-attachments/assets/bfc1702d-a30d-4762-ba3b-60b840c95180)

Then click Save.
Here, we will create 2 limiters with "1MP_DOWNLOAD" and "1MB_UPLOAD".
![image](https://github.com/user-attachments/assets/b9d84d87-ca62-4f8d-a215-d6e985bbfa16)


Then go back to Aliases and create an Alias for Traffic Shaping for each machine.

![image](https://github.com/user-attachments/assets/67cc917c-a2a4-4752-869a-190e0c8c3e2a)



Test speed before applying.

![image](https://github.com/user-attachments/assets/6b4af539-1eb6-440a-8d93-0773e02d405b)


Create a rule to apply. Here, we will apply it to all protocols, set Action to Pass.

![image](https://github.com/user-attachments/assets/0bba5894-609f-419e-9dc7-7ed2b1a0c066)

Go to Advanced Options and scroll down to the bottom. In the In/Out pipe section, set "in" to "1MB_UPLOAD" and "out" to "1MB_DOWNLOAD".

Then save.


And restart the test. Download and upload speeds for the desired PC are now limited. We can add more PCs to limit in the Alias section.
![image](https://github.com/user-attachments/assets/6761b98e-1d53-42c1-8fff-861de47c7c51)

**8. Captive Portal:**

**Purpose:** Create a mandatory login page for users wanting to access the Wi-Fi network.

**Implementation Steps:**

**Installation:**

**Services > Captive Portal > Add**

![image](https://github.com/user-attachments/assets/3ca0fe0d-4fe3-45a9-bf64-c2dbee116255)


**Create a Zone:**

![image](https://github.com/user-attachments/assets/ac971ddd-cd1d-4d2c-97ec-4282645f7b15)


**Enable Captive Portal** to show configurations. Here, we will choose the LAN network.
![image](https://github.com/user-attachments/assets/f648d6bc-8aca-402b-9bf2-0bd3d12444d9)

Customize one of the two themes.

Templates can be found on GitHub. Here, we will take a sample template from GitHub.

![image](https://github.com/user-attachments/assets/61be41d7-bd6b-4ffb-ade3-9de0ce5f40ce)


**Authentication Method:** Customize security. Here, I will choose "Use an Authentication backend".

![image](https://github.com/user-attachments/assets/b8c7410a-675f-4575-acef-3f4bf8601c6f)

Then save.

![image](https://github.com/user-attachments/assets/756d0b66-b13c-4184-98ca-e73999a370f0)

Go to **System > User Manager > User > Edit**

Create users here and save (it doesn't allow spaces in the name, in the image, I accidentally included one :)).

![image](https://github.com/user-attachments/assets/3c5fe916-f035-42d6-9627-315b8a4d1d5f)


Go to the Action section to edit the user class to be suitable for the captive portal.


Click "Add privileges" and select the options as shown above, then save.

![image](https://github.com/user-attachments/assets/22df3d79-1f01-4245-a791-1b8218dec5b2)


After that, every time a user from a LAN PC wants to access a website, they will have to enter the username and password created above.

![image](https://github.com/user-attachments/assets/f9c7db6b-5b8e-424d-8c06-2dbb09137eb4)


**9. Blocking File Downloads by File Format**

Here, we will block .exe files like this (using SquidGuard).

![image](https://github.com/user-attachments/assets/02330c4f-4616-4988-9598-604331179c39)

Go to the **Target Categories** section.

![image](https://github.com/user-attachments/assets/990a3e6c-d5df-4c66-8da0-1605f93645be)


Click Add to create a blacklist for .exe files. Define the file format as .exe.
![image](https://github.com/user-attachments/assets/7956befb-b288-402c-bebc-0220c5c24c17)




Add a message :D and save.

![image](https://github.com/user-attachments/assets/a0606764-d229-4820-b7a7-62ef5fa35962)


In the **Common ACL** section, adjust the newly created Target, ensuring it is set to Deny.



Then apply the changes.


Go back to the website and download again.

(Image showing blocked .exe download message)

**Result :D** (Download of .exe file blocked successfully)
