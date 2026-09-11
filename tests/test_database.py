from database.db import AlertStore


def test_database(tmp_path):

    database_path = (
        tmp_path / "test.db"
    )

    store = AlertStore(
        str(database_path)
    )

    alert = {
        "rule": "PORT_SCAN",
        "severity": "HIGH",
        "description": "Test alert",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 1234,
        "dst_port": 80,
        "proto": "TCP",
        "confidence": 0.9,
    }

    store.save(alert)

    alerts = store.recent()

    assert len(alerts) == 1
    assert alerts[0]["rule"] == "PORT_SCAN"

    stats = store.stats()

    assert stats["total"] == 1

    store.close()
