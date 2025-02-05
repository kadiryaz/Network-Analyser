from pyflowmeter.sniffer import create_sniffer

sniffer = create_sniffer(
            # input_file='tests/pcap_files/pkt.UDP.null.pcapng',
            server_endpoint='http://127.0.0.1:5000/send_traffic',
            # to_csv=True,
            # output_file='./flows_test.csv',
            verbose=False,
            sending_interval=5
        )

sniffer.start()
try:
    sniffer.join()
except KeyboardInterrupt:
    print('Stopping the sniffer')
    sniffer.stop()
finally:
    sniffer.join()
