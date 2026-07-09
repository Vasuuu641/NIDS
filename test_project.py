from project import load_config, get_enabled_detectors, build_packet_callback
from nids.alerts import Alert


def test_load_config():
    config = load_config()
    assert "rules" in config
    assert "capture" in config


def test_get_enabled_detectors():
    config = load_config()
    detectors = get_enabled_detectors(config)
    assert isinstance(detectors, list)
    assert len(detectors) > 0


def test_build_packet_callback():
    alerts_received = []

    def fake_detector(packet):
        return Alert(
            attack_type="TEST",
            source_ip="127.0.0.1",
            severity="LOW",
            message="test"
        )

    callback = build_packet_callback([fake_detector])
    assert callable(callback)