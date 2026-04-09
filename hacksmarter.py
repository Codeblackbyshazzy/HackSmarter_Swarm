# main.py
import argparse
import os
from langgraph.graph import StateGraph, END
from state import PentestState
from agents import recon_node, vuln_node, strategy_node
from tools import run_nuclei_tool, execute_curl_request, run_nmap_tool, DB_PATH
from langgraph.checkpoint.memory import MemorySaver

# 1. Initialize the Graph with our State
workflow = StateGraph(PentestState)
memory = MemorySaver()

# 2. Add the Nodes (The Agents)
workflow.add_node("recon", recon_node)
workflow.add_node("vuln", vuln_node)
workflow.add_node("strategy", strategy_node)

def parse_targets(target_input: str) -> list:
    """Parses targets from string, comma-separated string, or file."""
    raw_targets = []
    if os.path.isfile(target_input):
        with open(target_input, 'r') as f:
            for line in f:
                parts = line.strip().split(',')
                raw_targets.extend(parts)
    else:
        raw_targets = target_input.split(',')
    
    return [t.strip() for t in raw_targets if t.strip()]

# 3. Define the routing logic (Conditional Edge)
def router(state: PentestState):
    """Routes the graph based on the Strategy Node's decision."""
    
    # FIX: Change "complete" to "COMPLETE" to match what strategy_node outputs!
    if state.get("current_phase") == "COMPLETE":
        return "end"   # Maps to END in your dictionary
        
    return "pivot"     # Maps to "recon" in your dictionary

# 4. Add the Edges (The Flow)
workflow.set_entry_point("recon")               # Always start with Recon
workflow.add_edge("recon", "vuln")              # Recon always flows to Vuln
workflow.add_edge("vuln", "strategy")           # Vuln always flows to Strategy

# The Conditional Edge: Based on 'router', go to END or back to Recon
workflow.add_conditional_edges(
    "strategy",
    router,
    {
        "end": END,
        "pivot": "recon" 
    }
)

# 5. Compile the application
app = workflow.compile(checkpointer=memory)

# --- Execution ---
if __name__ == "__main__":
    print("[*] Initializing the Hack Smarter Swarm...")

    # 1. Handle Arguments
    parser = argparse.ArgumentParser(description="Hack Smarter AI Swarm. Built to assist, not replace.")
    parser.add_argument("-t", "--target", required=True, help="Target(s) or file path")
    args = parser.parse_args()

    targets = parse_targets(args.target)
    print(f"[*] Loaded {len(targets)} target(s).")

    # 2. Iterate through targets
    for index, target in enumerate(targets):
        print(f"\n{'='*40}\n[*] DEPLOYING AGAINST: {target}\n{'='*40}")

        initial_state = {
            "target_domain": target, 
            "subdomains": [],
            "open_ports": [],
            "vulnerabilities": [],
            "last_vuln_count": -1,
            "current_phase": "start",
            "strategy_directives": "",
            "markdown_report": "",
            "dradis_json": {}
        }

        # Unique thread_id per target to keep the AI's "brains" separated
        config = {
            "configurable": {"thread_id": f"run_{index}"}, 
            "recursion_limit": 15
        }

        try:
            # 3. Run the graph
            final_state = app.invoke(initial_state, config=config)
            
            # 4. Success Check
            # We check the phase, because the Node already handled the file saving.
            if final_state.get("current_phase") == "COMPLETE":
                print(f"[*] Swarm successfully completed operations on {target}.")
                print(f"[*] Artifacts generated: dradis_import.json, final_report.md")
            else:
                print(f"\n[!] Swarm stopped early in phase: {final_state.get('current_phase')}")

        except Exception as e:
            print(f"\n[!] Swarm error on {target}: {e}")
            continue # Don't let one bad target kill the whole list

    print("\n[*] All targets processed.")