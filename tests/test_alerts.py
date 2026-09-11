from alerts.alert_manager import AlertManager


def test_alert_manager():

    saved = []

    manager = AlertManager(
        on_alert=saved.append
    )

    alert = {
        "rule": "PORT_SCAN",
        "severity": "HIGH",
        "description": "Test port scan",
        "src_ip": "192.168.1.50",
        "dst_ip": "192.168.1.1",
        "src_port": 40000,
        "dst_port": 80,
        "proto": "TCP",
        "confidence": 0.9,
    }

    result = manager.process(
        alert
    )

    assert result is not None
    assert len(saved) == 1
    assert saved[0]["rule"] == "PORT_SCAN"


def test_alert_deduplication():

    saved = []

    manager = AlertManager(
        on_alert=saved.append
    )

    alert = {
        "rule": "PORT_SCAN",
        "severity": "HIGH",
        "description": "Test",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 1234,
        "dst_port": 80,
        "proto": "TCP",
        "confidence": 0.9,
    }

    first = manager.process(alert)
    second = manager.process(alert)

    assert first is not None
    assert second is None
    assert len(saved) == 1
