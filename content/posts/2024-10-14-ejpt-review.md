---
title: eJPT Review
author: 0xbhsu
description: Course and exam review
date: '2024-10-14'
toc: true
---



## Introduction
On 13/10/2024, I obtained the eJPT certification after two months of preparation, following the iNE course. This article aims to provide an analysis of the course and exam, as well as some useful tips for preparation. I was able to complete the exam in the first 6 hours, without facing many difficulties.

The certification is valid for **3 years** from the approval date.

The certification costs **$200**, including access to the course and 3 months of Fundamentals Learning. However, iNE occasionally offers some $50 discount coupons.



## Course Content
The preparatory course consists of 4 sections, organized into 12 modules and 240 videos, covering the entire pentesting process from start to finish. The course’s goal is not to be extremely specific or advanced but to provide an overview and cover the basics.

The main topics covered in the course include:

- **Information Gathering**  
    Techniques for passive and active information gathering. Topics include DNS recon, subdomain enumeration, Google Dorks, DNS zone transfer, and basic use of Nmap.

- **Footprinting & Scanning**  
    Fundamentals of computer networks, host discovery (ping sweep), use of the Nmap Scripting Engine (NSE), firewall detection, and IDS evasion.

- **Enumeration**  
    Enumeration of protocols/services such as SMB, FTP, SSH, and HTTP.

- **System/Host-Based Attacks**  
    Exploiting vulnerabilities in Windows and Linux systems, including privilege escalation techniques.

- **Network-Based Attacks**  
    In-depth firewall detection and IDS evasion, as well as detailed enumeration of SMB/NetBIOS and SNMP.

- **The Metasploit Framework (MSF)**  
    Comprehensive review of the Metasploit Framework, including enumeration of protocols/technologies like FTP, SMB, MySQL, SSH, and SMTP. Use of **msfvenom** and exploitation/post-exploitation in Windows and Linux.

- **Exploitation**  
    Shell basics such as bind and reverse shells, PowerShell-Empire, exploitation of vulnerabilities in Windows (IIS FTP, OpenSSH, SMB, MySQL) and Linux (vsFTPd, PHP, SAMBA), as well as basic antivirus evasion.

- **Post-exploitation**  
    Post-exploitation enumeration in Linux and Windows, file transfer, shells, privilege escalation, persistence, password dumping and cracking, pivoting, and cleanup.

The topics are introductory, aimed at beginners. Sometimes, the course repeats the same subjects, becoming a bit repetitive.

I skipped some courses, such as **Vulnerability Assessment**, **Auditing Fundamentals**, and **Social Engineering**.

Since 02/10/2024, the progress marking of videos [can no longer be done manually](https://learn.ine.com/product-updates/removing-mark-finished), meaning you need to watch the videos entirely without skipping any parts for them to be marked as completed.



## Preparation
During my preparation, besides the course content, I have done some HackTheBox and VulnHub machines, which have similar content to the exam. In my opinion, the eJPT exam is at the same level as the easy HTB machines, meaning that being able to solve most of them can ensure an easier approval.

HackTheBox machines:
- [Grandpa](https://app.hackthebox.com/machines/13)
- [Nibbles](https://app.hackthebox.com/machines/121)
- [Devel](https://app.hackthebox.com/machines/3)
- [Legacy](https://app.hackthebox.com/machines/2)

VulnHub machines:
- [Kioptrix 1.0](https://www.vulnhub.com/entry/kioptrix-level-1-1,22/)
- [Kioptrix 1.3](https://www.vulnhub.com/entry/kioptrix-level-13-4,25/)
- [Kioptrix 1.4](https://www.vulnhub.com/entry/kioptrix-2014-5,62/)
- [billu_box 2.0](https://www.vulnhub.com/entry/billu-b0x-2,238/)
- [LazySysAdmin](https://www.vulnhub.com/entry/lazysysadmin-1,205/)
- [NullByte](https://www.vulnhub.com/entry/nullbyte-1,126/)

In the iNE course and while solving the machines, I took notes using [Obsidian](https://obsidian.md/), making it easier to organize my notes and enabling quick and effective consultation.



## The Labs
Some topics within the courses include labs to practice what was studied, with some being CTF-style (requiring a specific flag to complete), while others are just for practice, without needing a flag to finish them.

The labs that do not require a flag are completed based on the time spent interacting with the lab. In other words, just interacting with the lab for a certain period ensures that it is marked as completed.

The labs that require a flag to be completed are more targeted, with clear instructions on what needs to be done to finish them.



## The Exam
I managed to finish the exam completely in less than 6 hours, compromising and escalating privileges on all hosts.

The exam is conducted in an online lab, similar to the course labs. All the necessary toolkit (tools, wordlists, etc.) to complete the exam is available on the KaliBox within the online lab.

The maximum time allowed to complete the exam is 48 hours, consisting of 35 questions, some of which are multiple choice and others related to dynamic flags (which change with each lab restart, requiring submission only once, regardless of lab restart). The final grade is not only based on the correct answers to the questions but also on the activities performed in the lab, such as specific interactions with targets (pivoting, command execution, file upload and download, etc.).

This means that even if you answer all 35 questions correctly, it is not guaranteed to pass with 100%, as the grade is composed of activities performed in the lab by interacting with the targets.

During the exam, internet access is allowed to search for exploits and consult your notes, so having well-organized material is essential.

The exam is very straightforward, without many rabbit holes. The biggest secret of the exam is definitely thorough reconnaissance and knowing exactly how to perform brute-force attacks.



## Conclusion
The eJPT is an introductory exam that thoroughly covers the topics from the preparatory course, such as reconnaissance, exploitation, pivoting, and file transfer.



## References
Some materials I used during my preparation:
- https://systemweakness.com/my-experience-of-the-free-ejptv2-exam-609beddab405#18cb
- https://alyamimohd.notion.site/Progress-cb2b498fe9ce4134aa4ab06bbdde9c74
- https://infosecwriteups.com/ejpt-v2-review-elearn-jpt-certification-423d7c940d9a
