# tools.py
import subprocess
import json
import re
from langchain_core.tools import tool
import os
from tqdm import tqdm
from typing import Union, List

DB_PATH = "pentest_db.json"
OUTPUT_DIR = "."
SKIP_CURRENT_TASK = False

def set_output_dir(path: str):
    """Sets the global output directory and updates DB_PATH."""
    global OUTPUT_DIR, DB_PATH
    OUTPUT_DIR = path
    DB_PATH = os.path.join(path, "pentest_db.json")

def update_db(key: str, new_data: list):
    # Default structure
    db = {"subdomains": [], "open_ports": [], "vulnerabilities": [], "interesting_files": [], "tool_runs": {}}
    
    if os.path.exists(DB_PATH):
        with open(DB_PATH, "r") as f:
            try:
                # Merge existing data into the default structure
                existing_db = json.load(f)
                db.update(existing_db)
            except json.JSONDecodeError:
                pass

    # Deduplicate and merge
    current_list = db.get(key, [])
    for item in new_data:
        if item not in current_list:
            current_list.append(item)
    
    db[key] = current_list
    with open(DB_PATH, "w") as f:
        json.dump(db, f, indent=4)
    return db[key]

def is_already_run(tool_name: str, target: str) -> bool:
    """Checks if a tool has already been run against a target in this database."""
    if not os.path.exists(DB_PATH):
        return False
    with open(DB_PATH, "r") as f:
        try:
            db = json.load(f)
            # The key in tool_runs is the tool's common name
            runs = db.get("tool_runs", {}).get(tool_name, [])
            return target in runs
        except json.JSONDecodeError:
            return False

def mark_as_run(tool_name: str, target: str):
    """Marks a tool as having been run against a target."""
    db = {"subdomains": [], "open_ports": [], "vulnerabilities": [], "interesting_files": [], "tool_runs": {}}
    if os.path.exists(DB_PATH):
        with open(DB_PATH, "r") as f:
            try:
                existing_db = json.load(f)
                db.update(existing_db)
            except json.JSONDecodeError:
                pass
    
    if "tool_runs" not in db:
        db["tool_runs"] = {}
        
    tool_runs = db["tool_runs"]
    if tool_name not in tool_runs:
        tool_runs[tool_name] = []
    
    if target not in tool_runs[tool_name]:
        tool_runs[tool_name].append(target)
    
    db["tool_runs"] = tool_runs
    with open(DB_PATH, "w") as f:
        json.dump(db, f, indent=4)

def filter_live_targets_httpx(targets: list) -> list:
    """
    Takes a list of raw URLs/Domains, pipes them into httpx, 
    and returns only the ones that respond with a live web server.
    """
    print(f"[*] Probing {len(targets)} potential targets with httpx...")
    if not targets:
        return []
        
    try:
        input_data = "\n".join(targets)
        
        # REMOVED check=True. We want the output even if it exits with status 1
        result = subprocess.run(
            ['httpx-toolkit', '-silent'], # Changed from 'httpx'
            input=input_data,
            capture_output=True, text=True
        )
        
        output = result.stdout.strip()
        
        # If output is totally empty, it means 0 live hosts (or a catastrophic crash)
        if not output:
            if result.returncode != 0 and result.stderr:
                print(f"[!] httpx error output: {result.stderr.strip()}")
            return []
            
        # Parse the output into a clean list of verified URLs
        live_urls = [line.strip() for line in output.split('\n') if line.strip()]
        return live_urls
        
    except FileNotFoundError:
        print("[!] httpx binary not found! Falling back to raw target list. Make sure it's installed and in your PATH.")
        return targets
    except Exception as e:
        print(f"[!] Unexpected httpx error: {e}. Falling back to raw target list.")
        return targets

@tool
def run_httpx_tool(targets: Union[str, List[str]]) -> List[str]:
    """
    Takes a single target or a list of targets (URLs/domains), 
    probes them with httpx, and returns a list of only the live web servers.
    Use this to verify if a target is alive before running dirsearch or wpscan.
    """
    target_list = [targets] if isinstance(targets, str) else targets
    return filter_live_targets_httpx(target_list)

@tool
def format_scope_tool(scope: str) -> dict:
    """
    Analyzes the user-provided scope and categorizes it.
    Args: scope (str): The raw input (e.g., '192.168.1.1', 'example.com', '10.0.0.0/24')
    """
    # Basic regex for IP vs Domain (You can expand this for CIDR)
    is_ip = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", scope)
    
    return {
        "original_scope": scope,
        "type": "IP" if is_ip else "Domain",
        "ready_for_nmap": bool(is_ip),
        "ready_for_subfinder": not bool(is_ip)
    }

@tool
def run_subfinder_tool(domain: str) -> str:
    """
    Finds subdomains for a given target domain using subfinder.
    Returns a success message with the count of subdomains found. 
    This list should be considered the exhaustive source of truth for subdomains.
    """
    if is_already_run("subfinder", domain):
        return f"[!] Skipping subfinder for {domain} - Results already in database."
        
    global SKIP_CURRENT_TASK
    print(f"[*] Recon Agent executing subfinder on {domain}...")
    try:
        result = subprocess.run(['subfinder', '-d', domain, '-silent'], capture_output=True, text=True)
        
        if SKIP_CURRENT_TASK:
            SKIP_CURRENT_TASK = False
            mark_as_run("subfinder", domain)
            print(f"\n[!] Subfinder scan for {domain} skipped (User Interrupt).")
            return f"Subfinder scan for {domain} was skipped by user."
            
    except KeyboardInterrupt:
        SKIP_CURRENT_TASK = False
        mark_as_run("subfinder", domain)
        print(f"\n[!] Subfinder scan for {domain} interrupted by user. Skipping.")
        return f"Subfinder scan for {domain} was skipped by user."
    except subprocess.CalledProcessError as e:
        return f"Subfinder command failed. Error: {e.stderr}"
    except Exception as e:
        return f"An unexpected error occurred: {str(e)}"
    
    output = result.stdout.strip()
    
    if not output:
        mark_as_run("subfinder", domain)
        return f"Subfinder scan completed for {domain}. Result: 0 subdomains discovered. This is a valid result."

    # Parse plain text output (one subdomain per line)
    subdomains = [line.strip() for line in output.split('\n') if line.strip()]
            
    update_db("subdomains", subdomains)
    mark_as_run("subfinder", domain)
    return f"Subfinder scan successful for {domain}. Found {len(subdomains)} subdomains: {', '.join(subdomains)}"

@tool
def run_nmap_tool(target: str) -> list:
    """
    Runs a fast nmap port scan against a target IP or domain.
    Args: target (str): The IP or domain to scan.
    """
    if is_already_run("nmap", target):
        return f"[!] Skipping nmap for {target} - Results already in database."

    global SKIP_CURRENT_TASK
    try:
        print(f"[*] Recon Agent executing nmap on {target}...")
        result = subprocess.run(['nmap', '-F', '-T4', '--open', '-oG', '-', target], capture_output=True, text=True)
        
        if SKIP_CURRENT_TASK:
            SKIP_CURRENT_TASK = False
            mark_as_run("nmap", target)
            print(f"\n[!] Nmap scan for {target} skipped (User Interrupt).")
            return f"Nmap scan for {target} was skipped by user."
            
    except KeyboardInterrupt:
        SKIP_CURRENT_TASK = False
        mark_as_run("nmap", target)
        print(f"\n[!] Nmap scan for {target} interrupted by user. Skipping.")
        return f"Nmap scan for {target} was skipped by user."
    except subprocess.CalledProcessError as e:
        return [{"error": f"Nmap failed: {e.stderr}"}]

    open_ports = []
    for line in result.stdout.split('\n'):
        if "Ports:" in line:
            # Extract the port numbers (Grepable output parsing)
            ports_section = line.split("Ports: ")[1]
            for port_data in ports_section.split(', '):
                if "/open/" in port_data:
                    port_num = port_data.split('/')[0].strip()
                    open_ports.append({"target": target, "port": port_num})
                        
    update_db("open_ports", open_ports)
    mark_as_run("nmap", target)
    ports_list = [p['port'] for p in open_ports]
    return f"Nmap successful for {target}. Found {len(open_ports)} open ports: {', '.join(ports_list)}"

@tool
def run_nuclei_tool(targets: list, verbose: bool = False) -> str:
    """
    Runs Nuclei against a list of targets and safely parses the JSON output into the DB.
    Args: 
        targets (list): A list of target URLs to scan.
        verbose (bool): If True, shows raw Nuclei output in the terminal.
    """
    global SKIP_CURRENT_TASK
    out_file = os.path.join(OUTPUT_DIR, 'nuclei_out.json')
    
    # 1. Clean up old output files to prevent cross-contamination
    if os.path.exists(out_file):
        os.remove(out_file)

    if not targets:
        return "No targets provided to Nuclei."

    print(f"[*] Recon Agent executing Nuclei on {len(targets)} targets...")
    try:
        # Run optimized nuclei command
        # Passing targets via stdin to handle multiple URLs safely and aggregated rate limiting
        input_data = "\n".join(targets)
        
        cmd = [
            'nuclei', 
            '-je', out_file, 
            '-severity', 'low,medium,high,critical',
            '-exclude-tags', 'dos,fuzz',  # CRITICAL: Exclude templates that crash or overload servers
            '-rl', '5',                   # Hard throttle: Maximum 5 requests per second 
            '-c', '5',                    # Concurrency: Only 5 active templates at a time
            '-timeout', '10',             # Give the smaller servers 10 seconds to reply
            '-retries', '0',              # If a request drops, let it fail. Do NOT retry and compound the DoS.
            '-mhe', '3'      
        ]
        
        if verbose:
            cmd.append("-v")
            
        # Add stats for the progress bar
        cmd.extend(["-stats", "-stats-json", "-stats-interval", "1"])
            
        # Scrub GOOGLE_API_KEY
        nuclei_env = os.environ.copy()
        if "GOOGLE_API_KEY" in nuclei_env:
            del nuclei_env["GOOGLE_API_KEY"]
            
        # Execute with real-time feedback
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=nuclei_env
        )
        
        # Write targets to stdin
        if input_data:
            process.stdin.write(input_data)
            process.stdin.close()
        
        pbar = None
        try:
            # Nuclei sends stats-json to stderr. 
            # We read from it to update our loading bar.
            for line in iter(process.stderr.readline, ''):
                if verbose:
                    # If the user wants raw output, give it to them
                    print(line.strip())
                
                try:
                    if "{" in line and "}" in line:
                        # Look for the JSON stats line
                        stats = json.loads(line[line.find("{"):line.rfind("}")+1])
                        total_reqs = int(stats.get("total", 0))
                        curr_reqs = int(stats.get("requests", 0))
                        
                        if pbar is None and total_reqs > 0:
                            pbar = tqdm(total=total_reqs, desc="[*] Nuclei Progress", unit="req", leave=False)
                        
                        if pbar:
                            pbar.n = curr_reqs
                            pbar.refresh()
                except (json.JSONDecodeError, ValueError):
                    continue
        except KeyboardInterrupt:
            process.terminate()
            SKIP_CURRENT_TASK = False
            for t in targets:
                mark_as_run("nuclei", t)
            if pbar:
                pbar.close()
            print("\n[!] Nuclei scan interrupted by user. Skipping to next phase.")
            return "Nuclei scan was manually skipped. Moving to next verification phase."
                
        process.wait()
        if pbar:
            pbar.close()
            
        if SKIP_CURRENT_TASK:
            SKIP_CURRENT_TASK = False
            for t in targets:
                mark_as_run("nuclei", t)
            print("\n[!] Nuclei scan skipped (User Interrupt).")
            return "Nuclei scan was manually skipped."
        
        findings = []
        if os.path.exists(out_file):
            with open(out_file, 'r') as f:
                try:
                    # Try parsing as a single JSON array
                    parsed_data = json.load(f)
                    items = parsed_data if isinstance(parsed_data, list) else [parsed_data]
                except json.JSONDecodeError:
                    # Fallback to JSON Lines
                    f.seek(0)
                    items = [json.loads(line) for line in f if line.strip()]

                for item in items:
                    findings.append({
                        "template": item.get("template-id"),
                        # Grab the exact host/port Nuclei found it on
                        "target": item.get("matched-at", "unknown"), 
                        "severity": item.get("info", {}).get("severity"),
                        "description": item.get("info", {}).get("name")
                    })
            
            if findings:
                update_db("vulnerabilities", findings)
                return f"Nuclei complete. Added {len(findings)} findings to DB."
        
        return "Nuclei finished with 0 findings."
        
    except Exception as e:
        print(f"[!] Critical Nuclei Parsing Error: {str(e)}")
        return f"Nuclei tool error: {str(e)}"

@tool
def run_nc_banner_grab(target: str, port: int, send_string: str = "") -> str:
    """
    Uses netcat (nc) to grab a service banner or send a custom string to a port.
    Useful for manual verification of non-HTTP services.
    """
    try:
        # -w 2: 2 second timeout, -v: verbose, -n: no DNS
        cmd = ["nc", "-vn", "-w", "2", str(target), str(port)]
        # Add a newline to mimic echo's default behavior
        input_data = send_string + "\n"
        result = subprocess.run(cmd, input=input_data, capture_output=True, text=True)
        
        output = result.stdout if result.stdout else result.stderr
        return f"NC Output for {target}:{port}:\n{output}"
    except Exception as e:
        return f"NC Error: {str(e)}"

@tool
def run_ssh_audit(target: str, port: int = 22) -> str:
    """
    Runs ssh-audit to check for weak ciphers, algorithms, and vulnerabilities 
    like Terrapin (CVE-2023-48795).
    """
    try:
        # Assuming ssh-audit is installed via pip or apt
        result = subprocess.run(
            ['ssh-audit', '-p', str(port), target],
            capture_output=True, text=True
        )
        return f"SSH Audit Results for {target}:\n{result.stdout}"
    except Exception as e:
        return f"SSH Audit Error: {str(e)}"

@tool
def run_hydra_check(target: str, service: str, user: str, password: str, port: int = None) -> str:
    """
    Runs Hydra to verify if a specific username and password pair work on a service.
    Supported services: ssh, ftp, http-get, mysql, mssql, etc.
    """
    try:
        port_args = [f"-s", str(port)] if port else []
        # -l: user, -p: pass, -f: exit on found, -u: loop around users
        cmd = ["hydra", "-l", user, "-p", password] + port_args + ["-f", f"{service}://{target}"]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if "1 of 1 target successfully completed" in result.stdout:
            return f"[!] SUCCESS: Credentials verified! {user}:{password} works on {service}."
        return f"[-] FAILURE: Credentials {user}:{password} were rejected."
        
    except Exception as e:
        return f"Hydra Error: {str(e)}"

@tool
def run_testssl_verification(target: str) -> str:
    """
    Runs testssl.sh for a deep dive into SSL/TLS vulnerabilities.
    Only use this if Nuclei flags a specific SSL issue.
    """
    try:
        # --quiet: less noise, --severity MEDIUM: skip the fluff
        result = subprocess.run(
            ['testssl.sh', '--quiet', '--severity', 'MEDIUM', target],
            capture_output=True, text=True
        )
        return f"TestSSL Results for {target}:\n{result.stdout}"
    except Exception as e:
        return f"TestSSL Error: {str(e)}"

@tool
def execute_curl_request(url: str, method: str = "GET", headers: dict = None, data: str = None) -> str:
    """
    Executes a custom HTTP request using curl to verify vulnerabilities.
    Args: 
        url (str): The target URL.
        method (str): HTTP method (GET, POST, etc.)
        headers (dict): Optional headers.
        data (str): Optional payload body.
    """
    # Build the curl command safely
    cmd = ['curl', '-s', '-i', '-X', method, url]
    if headers:
        for k, v in headers.items():
            cmd.extend(['-H', f"{k}: {v}"])
    if data:
        cmd.extend(['-d', data])
        
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        # Return only the first 2000 characters to prevent blowing up the LLM context window
        return result.stdout[:2000] 
    except subprocess.TimeoutExpired:
        return "Error: Curl request timed out."
    except Exception as e:
        return f"Error: {str(e)}"

@tool
def run_wpscan_tool(target_url: str) -> str:
    """
    Runs WPScan against a target URL to check for WordPress installations, 
    vulnerabilities, and outdated plugins.
    Args: target_url (str): The URL to scan (e.g., http://example.com)
    """
    if is_already_run("wpscan", target_url):
        return f"[!] Skipping wpscan for {target_url} - Results already in database."

    print(f"[*] Recon Agent executing wpscan on {target_url}...")
    try:
        wpscan_token = os.environ.get("WPSCAN_API_TOKEN")
        token_args = ["--api-token", wpscan_token] if wpscan_token else []

        # Try running without update first for speed
        try:
            result = subprocess.run(
                ['wpscan', '--url', target_url, '--no-update', '--random-user-agent', '-e', 'vp,vt'] + token_args,
                capture_output=True, text=True
            )
        except KeyboardInterrupt:
            print("\n[!] WPScan interrupted by user. Skipping.")
            mark_as_run("wpscan", target_url)
            return "WPScan interrupted by user."
        
        # Check if it failed due to missing database
        if "missing database" in (result.stdout + result.stderr).lower():
            print("[!] WPScan database missing. Attempting update...")
            subprocess.run(['wpscan', '--update'], capture_output=True, text=True)
            # Retry after update
            try:
                result = subprocess.run(
                    ['wpscan', '--url', target_url, '--no-update', '--random-user-agent', '-e', 'vp,vt'],
                    capture_output=True, text=True
                )
            except KeyboardInterrupt:
                mark_as_run("wpscan", target_url)
                return "WPScan interrupted by user."
        
        output = result.stdout if result.stdout else result.stderr
        
        # Mark as run
        mark_as_run("wpscan", target_url)

        # Return truncated output to prevent LLM context blowup
        return f"WPScan Results for {target_url}:\n{output[:3000]}"
    except FileNotFoundError:
        return "[!] WPScan binary not found! Make sure it is installed and in your PATH."
    except Exception as e:
        return f"WPScan Error: {str(e)}"

@tool
def add_vulnerability_tool(target: str, template: str, severity: str, description: str, poc: str) -> str:
    """
    Manually adds a verified vulnerability to the database.
    Use this when you have verified a finding (e.g., via curl or other manual tools) 
    that was not automatically added by Nuclei.
    Args:
        target (str): The target URL or host.
        template (str): A name or ID for the vulnerability (e.g., 'git-config-disclosure').
        severity (str): low, medium, high, or critical.
        description (str): A brief description of the finding.
        poc (str): A proof of concept (the command/output used to verify).
    """
    finding = {
        "template": template,
        "target": target,
        "severity": severity,
        "description": description,
        "poc": poc 
    }
    update_db("vulnerabilities", [finding])
    return f"Successfully added vulnerability '{template}' for {target} to the database."

@tool
def run_feroxbuster_tool(url: Union[str, List[str]], extensions: str = "php,html,js,txt", verbose: bool = False) -> str:
    """
    Performs directory and file discovery on a web server using feroxbuster.
    Args:
        url (Union[str, List[str]]): The target URL or a list of target URLs.
        extensions (str): Comma-separated list of extensions to check (default: php,html,js,txt).
        verbose (bool): If True, shows raw feroxbuster output in the terminal.
    """
    global SKIP_CURRENT_TASK
    targets = [url] if isinstance(url, str) else url
    
    # Filter targets that were already run
    new_targets = [t for t in targets if not is_already_run("feroxbuster", t)]
    
    if not new_targets:
        return f"All {len(targets)} targets have already been scanned by feroxbuster."

    print(f"[*] Sequential Scan: Executing feroxbuster on {len(new_targets)} targets one by one...")
    out_file = os.path.join(OUTPUT_DIR, 'feroxbuster_out.json')
    all_findings = []
    
    for i, target in enumerate(new_targets):
        if os.path.exists(out_file):
            os.remove(out_file)
            
        try:
            # Feroxbuster command for a single target
            cmd = [
                'feroxbuster',
                '-u', target,
                '-t', '10', # Respecting the user's manual change to 10 threads
                '-d', '2',
                '--json',
                '-o', out_file,
                '-x', extensions,
                '--no-state' 
            ]
            
            # Message to the user since we removed the loading bar
            print(f"[*] [{i+1}/{len(new_targets)}] Deep Discovery: Exploring {target}")
            print(f"    - Feroxbuster is performing exhaustive directory brute-forcing.")
            print(f"    - This can take several minutes per target. Please stand by...")
            
            # Use silent for the background process to keep terminal clean
            if not verbose:
                cmd.append('--silent')
                
            # Run feroxbuster synchronously for this target
            try:
                subprocess.run(
                    cmd,
                    capture_output=not verbose, 
                    text=True, 
                    check=False
                )
            except KeyboardInterrupt:
                SKIP_CURRENT_TASK = False
                mark_as_run("feroxbuster", target)
                print(f"\n[!] User skip requested for {target}. Moving to next target...")
                continue
            
            if SKIP_CURRENT_TASK:
                SKIP_CURRENT_TASK = False
                mark_as_run("feroxbuster", target)
                print(f"\n[!] User skip requested for {target}. Moving to next target...")
                continue
            
            target_findings = []
            if os.path.exists(out_file):
                with open(out_file, 'r') as f:
                    for line in f:
                        try:
                            data = json.loads(line)
                            if data.get("type") == "response":
                                status = data.get("status")
                                # Filter for interesting status codes
                                if status in [200, 301, 302]:
                                    target_findings.append({
                                        "url": data.get("url"),
                                        "status": status,
                                        "content-length": data.get("content_length"),
                                        "path": data.get("path")
                                    })
                        except json.JSONDecodeError:
                            continue
                
                if target_findings:
                    update_db("interesting_files", target_findings)
                    all_findings.extend(target_findings)
            
            # Mark THIS target as run before moving to the next
            mark_as_run("feroxbuster", target)

        except Exception as e:
            print(f"[!] Error scanning {target}: {str(e)}")
            continue

    if all_findings:
        # Return a global summary to the LLM
        summary = "\n".join([f"Found: {f['url']} (Status: {f['status']})" for f in all_findings[:10]])
        if len(all_findings) > 10:
            summary += f"\n... and {len(all_findings) - 10} more."
        return f"Feroxbuster sequential scan complete. Added {len(all_findings)} findings to DB across {len(new_targets)} targets.\nRecent discoveries:\n{summary}"
        
    return f"Feroxbuster sequential scan finished on {len(new_targets)} targets with 0 interesting findings."