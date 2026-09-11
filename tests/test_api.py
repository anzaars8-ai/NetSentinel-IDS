from database.db import AlertStore

from features.flow_tracker import FlowTracker

from api.app import create_app


def test_api(tmp_path):

    store = AlertStore(
        str(tmp_path / "api.db")
    )

    tracker = FlowTracker(10)

    app = create_app(
        store,
        tracker
    )

    client = app.test_client()

    response = client.get(
        "/api/health"
    )

    assert response.status_code == 200

    assert response.json["status"] == "ok"

    response = client.get(
        "/api/alerts"
    )

    assert response.status_code == 200
    assert response.json == []

    store.close()
