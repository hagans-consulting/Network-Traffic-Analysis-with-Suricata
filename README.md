# Network Traffic Analysis with Suricata
Course: Blue Team SOC Foundations
Module: IDS/IPS Deployment & Traffic Analysis
Date: June 24, 2026
Prerequisites: Lab 101 Completed, Ubuntu 24.04, GitHub Account

# Lab Overview
In this lab, you will deploy *Suricata*, a leading open-source Intrusion Detection System (IDS). You will configure it to monitor your home network traffic, generate simulated attack traffic using *Nmap*, and analyze the resulting alerts. This mirrors the daily workflow of a SOC Analyst monitoring Security Information and Event Management (SIEM) dashboards. 

Key Learning Objectives:

Install and configure Suricata via CLI.
Understand *HOME_NET* vs. *EXTERNAL_NET* variables.
Generate and detect malicious traffic patterns (Port Scans, ICMP floods).
Analyze JSON logs (*eve.json*) using *jq*. 
