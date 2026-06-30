from nids.alerts import Alert
from nids.storage import save

test_alert = Alert(
    attack_type="TEST",
    source_ip="127.0.0.1",
    severity="LOW",
    message="manual test"
)
print("Calling save()...")
save(test_alert)
print("save() returned")
