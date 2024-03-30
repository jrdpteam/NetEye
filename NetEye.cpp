#include <iostream>
#include <fstream>
#include <pcap.h>
#include <boost/asio.hpp>
#include <unistd.h>
#include <getopt.h>
#include <cstdlib>
#include <regex>

using namespace std;

void setTerminalWindowTitle() {
    cout << "\033]0;NetEye v3.0 by JRDP Team\007";
}

string highlightText(const string& text) {
    return "\033[1;31m" + text + "\033[0m";
}

void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packetData) {
    int ip_header_length = (packetData[14] & 0x0F) * 4;

    const u_char* data = packetData + ip_header_length;

    size_t data_length = pkthdr->len - ip_header_length;
    string text(reinterpret_cast<const char*>(data), data_length);

    string packetType;
    if (packetData[23] == 0x11) {
        packetType = "\033[1;34mUDP\033[0m";
    } else if (packetData[23] == 0x06) {
        packetType = "\033[1;31mTCP\033[0m";
    } else {
        packetType = "\033[1;33mUNKNOWN\033[0m";
    }

    string sourceIP = to_string((int)packetData[26]) + "." + to_string((int)packetData[27]) + "." + to_string((int)packetData[28]) + "." + to_string((int)packetData[29]);

    string destinationIP = to_string((int)packetData[30]) + "." + to_string((int)packetData[31]) + "." + to_string((int)packetData[32]) + "." + to_string((int)packetData[33]);

    static int packetNumber = 0;
    packetNumber++;

    cout << "\033[0m" << endl;
    cout << "\033[0;35m*****Nr " << packetNumber << "**********************************************************************************************************************************************************\033[0m" << endl;
    cout << "\033[0msource:\033[0m " << sourceIP << endl;
    cout << "\033[0mport:\033[0m " << (int)packetData[20] << endl;
    cout << "\033[0mdestination:\033[0m " << destinationIP << endl;
    cout << "\033[0msize:\033[0m " << pkthdr->len << " \033[0mbytes" << endl;
    cout << "\033[0mtype:\033[0m " << packetType << endl;
    cout << "\033[0menc:\033[0m " << "\033[1;33mUTF-8\033[0m" << endl;
    cout << "\033[0mtext:\033[0m " << highlightText(text) << endl;
    cout << "\033[0;35m********************************************************************************************************************************************************************\033[0m" << endl;
}

int main(int argc, char *argv[]) {
    if (getuid() != 0) {
        cerr << "NetEye requires root permissions.Try: sudo ./NetEye -i <interface>" << endl;
        return 1;
    }

    setTerminalWindowTitle();

    char errbuf[PCAP_ERRBUF_SIZE];
    string interface;

    int opt;
    while ((opt = getopt(argc, argv, "i:")) != -1) {
        switch (opt) {
            case 'i':
                interface = optarg;
                break;
            default:
                cerr << "Use: " << argv[0] << " -i <interfejs>" << endl;
                return 1;
        }
    }

    if (interface.empty()) {
        cerr << "Set interface using -i argument." << endl;
        return 1;
    }

    pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);

    pcap_loop(handle, 0, packetHandler, NULL);

    return 0;
}
