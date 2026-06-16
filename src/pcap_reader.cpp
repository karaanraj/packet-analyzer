#include "../include/pcap_reader.h"
#include <iostream>

bool PcapReader::open(const std::string& filename) {
    // Open file in binary mode
    file_.open(filename, std::ios::binary);
    if (!file_.is_open()) {
        std::cerr << "Cannot open file: " << filename << "\n";
        return false;
    }

    // Read and verify the global header
    PcapGlobalHeader header;
    file_.read((char*)&header, sizeof(header));

    // Magic number confirms this is a valid PCAP file
    if (header.magic_number != 0xa1b2c3d4) {
        std::cerr << "Not a valid PCAP file!\n";
        return false;
    }

    std::cout << "PCAP file opened successfully!\n";
    return true;
}

bool PcapReader::readNextPacket(RawPacket& packet) {
    // Try to read the 16-byte packet header
    file_.read((char*)&packet.header, sizeof(PcapPacketHeader));
    
    // If we couldn't read it, we've reached end of file
    if (!file_) return false;

    // Now read the actual packet bytes
    packet.data.resize(packet.header.incl_len);
    file_.read((char*)packet.data.data(), packet.header.incl_len);

    return true;
}

void PcapReader::close() {
    file_.close();
}