# Packet Capture Program

This program is a network packet capturing tool designed to allow users to capture, analyze, and visualize network traffic in real-time. It offers options to print packet information, extract headers, detect protocols, and calculate packet statistics.

## Features

- **Real-time packet capture**: Starts capturing packets on the specified network interface.
- **Packet information**: Displays basic information for each captured packet.
- **Header extraction**: Parses and displays packet headers.
- **Protocol detection**: Identifies protocols used in captured packets.
- **Capture statistics**: Calculates and displays statistics about captured packets, including total packets and protocol distribution.

## Requirements

To compile and run this program, you will need:

- A compatible C compiler (like GCC)
- The `libpcap` library installed on your system

The interface where the packet  capture will be performed is determined by the FILE is in config folder named "config.txt"

```
NETWORK_ADAPTER=ens
```
"ens" have to be replace by the name of  your network adapter. You can find it using the command `ifconfig`.

## Compilation

To compile the program, use the following command in the terminal:

```bash
cmake -DCMAKE_BUILD_TYPE=[Debug/Release] -Bbuild && cd build && make
```

## USAGE
To run the program, simply execute the compiled binary from the terminal:

```bash
./packet_capture
```

Once started, the program will display a menu with the following options:

Packet Capture Program Menu:
```
1. Start packet capture
2. Print packet information [ON/OFF]
3. Extract headers [ON/OFF]
4. Detect protocols [ON/OFF]
5. Calculate statistics [ON/OFF]
6. Exit
>
```
Select an option by entering the corresponding number and pressing Enter. Once the options wants are enable press 1 and Enter.

## Contributions

Contributions to this project are welcome. Please make sure to follow good coding and documentation practices.

## License

This project is distributed under the Apache License. See the LICENSE file for more details. 