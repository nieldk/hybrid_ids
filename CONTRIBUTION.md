
# Contributing to Hybrid IDS/IPS

Thank you for considering contributing to this open-source Hybrid Intrusion Detection and Prevention System project!

We welcome bug fixes, feature enhancements, documentation improvements, and ideas for extending the IDS/IPS functionality.

---

## Project Structure

- `hybrid_ids.py` — Main IDS/IPS Python script
- `INSTALL.md` — Installation and setup guide
- `FEATURES.md` — Detailed feature list
- `requirements.txt` — Python dependencies

---

## Development Setup

1. **Clone the repository:**

```bash
git clone https://github.com/nieldk/hybrid-ids.git
cd hybrid-ids
```

2. **Set up a virtual environment:**

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

3. **Test locally** (requires root privileges):

```bash
sudo python3 hybrid_ids.py
```

---

## Contribution Guidelines

- Write clear, descriptive commit messages.
- For significant changes, open an issue first to discuss your proposal.
- Follow existing code style and naming conventions.
- Include comments for new functions or logic.

---

## Testing

While there’s no automated test suite yet, contributors are encouraged to:

- Use sample PCAPs or test VMs for simulation.
- Log anomalies and verify firewall behavior (e.g. `iptables -L`).

---

## Submitting Pull Requests

1. Fork the repository
2. Create a new branch (`feature/your-feature`)
3. Make your changes
4. Push to your fork and submit a Pull Request

We review all PRs and will respond as quickly as possible.

---

## Questions or Suggestions?

Open an issue or start a discussion in the repository. We're open to all ideas for improving detection, response, and visualization.

Thanks for contributing! 
