# Firewall Rule Visualizer (Python)

This is a simple Python tool that reads firewall rules (from a JSON file) and creates a visual diagram to show how network traffic is allowed or blocked between sources and destinations.

### What it does:
- Loads rules from a JSON file (`firewall_rules.json`)
- If the file doesn’t exist, it creates one with some example rules
- Draws a clear network graph showing:
  - Who is talking to who
  - What ports and protocols are being used
  - Whether rules allow or deny access
  - Warnings for overly permissive "any-to-any" rules

### What you learn from it:
- Basic network security concepts
- Python data parsing
- Visualizing graphs using `networkx` and `matplotlib`

### Output
The script saves a diagram as `firewall_diagram.png` showing nodes (IP addresses) and how they're connected via rules.

### How to run
1. Install the required libraries:

   ```bash
   pip install -r requirements.txt
   ```

2. Run the script:

   ```bash
   python firewall_vis.py
   ```

3. The output image (`firewall_diagram.png`) will be created in the same folder.

---

### JSON file format

Each rule in `firewall_rules.json` looks like this:

```json
{
  "source": "192.168.1.10",
  "destination": "10.0.0.5",
  "port": "22",
  "protocol": "tcp",
  "action": "ALLOW"
}
```

You can modify or add your own rules.

---

### License

MIT License
