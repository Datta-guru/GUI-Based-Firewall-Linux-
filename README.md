# Firewall Rule Simulator

A GUI-based Firewall Rule Simulator built using Python that allows users to create, manage, and apply firewall rules easily without using complex command-line tools.

## Description

This project provides a simple interface to manage firewall rules. Users can define rules using parameters like source IP, destination IP, port, protocol, and action (ACCEPT, DROP, REJECT).

The application stores rules in a JSON file and applies them directly to the system firewall using iptables.

Example rules stored in the system:

## Features
Easy-to-use GUI (Tkinter)  
Add, delete, and reorder rules  
Input validation (IP & Port)  
Apply rules using iptables  
Persistent storage using JSON  
Prevents duplicate rules  
## Tech Stack
Python 3  
Tkinter (GUI)  
iptc (iptables integration)  
JSON (data storage)  
## Project Structure  
.  
├── main.py        # Main application file  
├── rules.json     # Stores firewall rules  

Main logic and GUI are implemented in:  

## Requirements
Linux OS (Arch / Ubuntu recommended)  
Python 3.x  
Root privileges  
iptables installed  
## Installation & Setup (Linux)
### Install Dependencies
#### Arch
sudo pacman -S python python-pip iptables   

#### OR (Ubuntu)
sudo apt update  
sudo apt install python3 python3-pip iptables  
### Install Python Libraries
pip install python-iptables
### Run the Application
sudo python main.py

Note: sudo is required to apply firewall rules.
