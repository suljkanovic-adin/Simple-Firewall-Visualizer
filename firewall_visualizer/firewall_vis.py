import json
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import os

# Example fallback rules
example_rules = [
    {"source": "192.168.1.10", "destination": "10.0.0.5", "port": "22", "protocol": "tcp", "action": "ALLOW"},
    {"source": "any", "destination": "10.0.0.10", "port": "80", "protocol": "tcp", "action": "ALLOW"},
    {"source": "any", "destination": "any", "port": "any", "protocol": "udp", "action": "ALLOW"},
    {"source": "10.0.0.2", "destination": "192.168.1.2", "port": "443", "protocol": "tcp", "action": "DENY"}
]

# Load firewall rules from JSON, or fallback to example
def load_rules(json_path):
    if not os.path.exists(json_path):
        print(f"File '{json_path}' not found. Creating one with example rules...")
        with open(json_path, 'w') as f:
            json.dump(example_rules, f, indent=4)
    try:
        with open(json_path, 'r') as f:
            rules = json.load(f)
        return rules
    except json.JSONDecodeError:
        print("Invalid JSON format.")
        return []

# Generate Graphviz diagram
def generate_graph(rules, output_path='firewall_diagram.png', highlight_action=None):
    G = nx.DiGraph()

    # Gather nodes and metrics
    node_counts = {}
    for rule in rules:
        src = rule.get("source", "any")
        dst = rule.get("destination", "any")
        node_counts[src] = node_counts.get(src, 0) + 1
        node_counts[dst] = node_counts.get(dst, 0) + 1

    unique_nodes = set(node_counts.keys())

    # Assign role and size
    for node in unique_nodes:
        if node == "any":
            G.add_node(node, role='generic', size=500)
        elif node.startswith(("192.", "10.", "172.")):
            G.add_node(node, role='internal', size=1200 + node_counts[node]*100)
        else:
            G.add_node(node, role='external', size=1000 + node_counts[node]*100)

    # Advanced edge styling and filter option
    for rule in rules:
        src = rule.get("source", "any")
        dst = rule.get("destination", "any")
        port = rule.get("port", "any")
        proto = rule.get("protocol", "any")
        action = rule.get("action", "ALLOW")

        if highlight_action and action.upper() != highlight_action.upper():
            continue  # Show only rules matching filter

        label = f"{proto.upper()}:{port} ({action})"
        warn_any = src == "any" and dst == "any" and action.upper() == "ALLOW"

        edge_color = 'orange' if warn_any else ('#2b83ba' if action.upper() == "ALLOW" else '#d7191c')
        edge_style = 'dashed' if action.upper() == "DENY" else 'solid'

        G.add_edge(src, dst, label=label, color=edge_color, style=edge_style, weight=2 + int(warn_any))

    # Choose layout based on graph size
    if len(G) > 10:
        pos = nx.kamada_kawai_layout(G)
    else:
        pos = nx.spring_layout(G, k=1.6, iterations=80)

    # Draw nodes by role
    role_shape_map = {'internal':'o', 'external':'s', 'generic':'d'}
    color_map = {'internal':'#b6e6bd', 'external':'#f7cac9', 'generic':'#ececec'}

    for role, shape in role_shape_map.items():
        nodelist = [n for n in G.nodes if G.nodes[n]['role'] == role]
        sizes = [G.nodes[n]['size'] for n in nodelist]
        nx.draw_networkx_nodes(
            G, pos,
            nodelist=nodelist,
            node_shape=shape,
            node_color=[color_map[role]]*len(nodelist),
            node_size=sizes, edgecolors='black', alpha=0.9
        )

    # Draw edges with custom styles
    for u, v, d in G.edges(data=True):
        nx.draw_networkx_edges(
            G, pos,
            edgelist=[(u,v)],
            style=d['style'],
            edge_color=d['color'],
            arrowstyle='-|>',
            arrowsize=20,
            width=d['weight'],
            alpha=0.85
        )

    # Draw node and edge labels
    nx.draw_networkx_labels(G, pos, font_size=9, font_weight='bold')
    edge_labels = nx.get_edge_attributes(G, 'label')
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=7)

    # Custom legend
    legend = [
        mpatches.Patch(color='#b6e6bd', label='Internal Node'),
        mpatches.Patch(color='#f7cac9', label='External Node'),
        mpatches.Patch(color='#ececec', label='Any/Generic Node'),
        mpatches.Patch(color='orange', label='ANY->ANY ALLOW'),
        mpatches.Patch(color='#2b83ba', label='ALLOW'),
        mpatches.Patch(color='#d7191c', label='DENY')
    ]
    plt.legend(handles=legend, loc='upper left', fontsize='small', ncol=1)

    plt.title("Firewall Rule Visualization (Enhanced)")
    plt.axis('off')
    plt.tight_layout()
    plt.savefig(output_path, bbox_inches='tight', dpi=130)
    plt.close()
    print(f"Diagram saved to {output_path}")

# Run the script
if __name__ == "__main__":
    filename = "firewall_rules.json"
    rules = load_rules(filename)
    if rules:
        generate_graph(rules)
