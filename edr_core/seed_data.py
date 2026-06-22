from .db import init_db
from .threat_intel import seed_intel_db


def main() -> None:
    init_db()
    seed_intel_db()
    print("Database and local threat-intelligence cache initialized.")


if __name__ == "__main__":
    main()

