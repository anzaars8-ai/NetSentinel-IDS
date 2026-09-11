from features.flow_tracker import FlowTracker


def test_flow_tracker():

    tracker = FlowTracker(10)

    for port in range(1, 21):

        tracker.update({
            "src_ip": "192.168.1.50",
            "dst_ip": "192.168.1.1",
            "proto": "TCP",
            "src_port": 40000 + port,
            "dst_port": port,
            "flags": "S",
            "length": 60,
        })

    stats = tracker.stats_for(
        "192.168.1.50"
    )

    assert stats.packets == 20
    assert stats.bytes_total == 1200
    assert len(stats.unique_ports) == 20
    assert stats.syns == 20
