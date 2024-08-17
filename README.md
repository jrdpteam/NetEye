# NetEye
Tiny sniffer made in C++.Designed for use on Kali Linux and other Debian-based linux distributions.

NetEye allows you to view your network traffic. You can see visited websites, analyze HTTP/HTTPS requests, cookie data, unencrypted UDP/TCP packets,messages and personal/login data. The project is still under development. by JRDP Team

To build NetEye you need to install g++ compiler using this command:

    sudo apt update && sudo apt install g++

And some required libraries:

    sudo apt install libpcap-dev libboost-all-dev

Then,open terminal on Your desktop and type this command to copy this repository:

    git clone https://github.com/JRDPCN/NetEye

Now,nawigate to NetEye directory on Your desktop and type this command to compile NetEye:

    g++ -o NetEye NetEye.cpp -lpcap -lboost_system -lboost_thread

Then,You should see executable file in this directory,without extension.
Run this command to allow this file to run as program:

    sudo chmod +x NetEye

Now,You can run NetEye:

    sudo ./NetEye -i INTERFACE

As "INTERFACE" use network interface of your device.Run *ifconfig* command to see available interfaces.

![NetEye](https://github.com/JRDPCN/NetEye/assets/136267216/83d73886-35d6-4a0f-b9d4-39bcccd02c9f)
