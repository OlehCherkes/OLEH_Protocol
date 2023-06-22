# OLEH_Protocol
Wireshark dissector

## Test run
- Copy the oleh.so file to the /usr/local/lib/wireshark/plugins/4.1/epan/ directory and run Wireshark.
- Go to "Help -> About Wireshark", go to the Plugins tab and in the list that appears, find our plugin - oleh.so
    - in my case sudo mv /home/oleh/wireshark/build/run/plugins/4.1/epan/oleh.so /usr/local/lib/wireshark/plugins/4.1/epan/oleh.so
- dissector is waiting for a data packet on port 7777
- run the test command echo "Hello, World!" | nc -u -w1 192.168.0.10 7777

## Assembly Plugin
- cmake .. -DCUSTOM_PLUGIN_SRC_DIR="plugins/epan/oleh"
- make
