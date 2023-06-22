# OLEH_Protocol
Wireshark dissector

## Test run
- Copy the oleh.so file from folder dissector to the */usr/local/lib/wireshark/plugins/4.1/epan/* directory and run Wireshark.
    - in my case *sudo mv /home/oleh/wireshark/build/run/plugins/4.1/epan/oleh.so /usr/local/lib/wireshark/plugins/4.1/epan/oleh.so*
- Go to "Help -> About Wireshark", go to the Plugins tab and in the list that appears, find our plugin - oleh.so
- run the test dissector (waiting for a data packet on port 7777)
    - command echo "Hello, World!" | nc -u -w1 192.168.0.10 7777
    - or use test_dissector.c from test folder

## Assembly Plugin
- cmake .. -DCUSTOM_PLUGIN_SRC_DIR="plugins/epan/oleh"
- make

## About the project
  ![promo](/doc/promo.png)

The dissector expects a UDP data packet on port 777.
Structure:
- 1 byte — protocol version
- 1 byte — packet type
- 1 byte — flags
- 1 byte — Boolean variable
- 4 bytes — data length
- From 0 — data
