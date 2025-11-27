#!/usr/bin/env python3
"""
YARA Scanner for LinProcMon Sandbox Output

Scans all sandbox_* directories for memory dumps and applies
meterpreter detection rules to verify payload capture.
"""

import os
import sys
import glob
from pathlib import Path
from collections import defaultdict

try:
    import yara
except ImportError:
    print("ERROR: yara-python not installed")
    print("Install with: pip install yara-python")
    sys.exit(1)

# Colors for terminal output
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    MAGENTA = '\033[0;35m'
    NC = '\033[0m'  # No Color

def print_header(text):
    """Print colored header"""
    print(f"{Colors.BLUE}{'=' * 60}{Colors.NC}")
    print(f"{Colors.CYAN}{text}{Colors.NC}")
    print(f"{Colors.BLUE}{'=' * 60}{Colors.NC}")

def print_success(text):
    """Print success message"""
    print(f"{Colors.GREEN}[✓] {text}{Colors.NC}")

def print_warning(text):
    """Print warning message"""
    print(f"{Colors.YELLOW}[!] {text}{Colors.NC}")

def print_error(text):
    """Print error message"""
    print(f"{Colors.RED}[✗] {text}{Colors.NC}")

def print_info(text):
    """Print info message"""
    print(f"{Colors.CYAN}[*] {text}{Colors.NC}")

def check_yara_installed():
    """Check if YARA Python module is available"""
    try:
        print_success(f"yara-python version: {yara.__version__}")
        return True
    except AttributeError:
        print_success("yara-python module loaded")
        return True

def find_sandbox_directories(base_path):
    """Find all sandbox_* directories"""
    sandbox_dirs = []
    for item in glob.glob(os.path.join(base_path, 'sandbox_*')):
        if os.path.isdir(item):
            sandbox_dirs.append(item)
    return sorted(sandbox_dirs)

def find_memory_dumps(sandbox_dir):
    """Find all memory dump files in a sandbox directory"""
    dump_files = []
    for root, dirs, files in os.walk(sandbox_dir):
        for file in files:
            if file.endswith('.dump') or file.endswith('.bin'):
                dump_files.append(os.path.join(root, file))
    return sorted(dump_files)

def scan_file_with_yara(yara_rules, dump_file):
    """Scan a single file with YARA rules"""
    try:
        matches = yara_rules.match(dump_file)
        return matches
    except Exception as e:
        print_error(f"Error scanning {dump_file}: {e}")
        return []

def parse_yara_matches(matches):
    """Parse YARA match objects and extract details"""
    results = []
    
    for match in matches:
        match_info = {
            'rule': match.rule,
            'strings': []
        }
        
        # Extract matched strings
        for string_match in match.strings:
            # string_match is a tuple: (offset, identifier, data)
            # But in some YARA versions it might be an object
            try:
                if hasattr(string_match, 'instances'):
                    # New YARA format with instances
                    for instance in string_match.instances:
                        offset = instance.offset
                        identifier = string_match.identifier
                        data = instance.matched_data
                        
                        # Format as hex if binary data
                        try:
                            if isinstance(data, bytes):
                                display_data = data.decode('utf-8', errors='replace')[:100]
                            else:
                                display_data = str(data)[:100]
                        except:
                            display_data = data.hex()[:100] if isinstance(data, bytes) else str(data)[:100]
                        
                        match_info['strings'].append(f"0x{offset:x}:${identifier}: {display_data}")
                else:
                    # Old YARA format with tuple
                    offset = string_match[0]
                    identifier = string_match[1]
                    data = string_match[2]
                    
                    # Format as hex if binary data
                    try:
                        if isinstance(data, bytes):
                            display_data = data.decode('utf-8', errors='replace')[:100]
                        else:
                            display_data = str(data)[:100]
                    except:
                        display_data = data.hex()[:100] if isinstance(data, bytes) else str(data)[:100]
                    
                    match_info['strings'].append(f"0x{offset:x}:${identifier}: {display_data}")
            except Exception as e:
                # Fallback: just show we found a match
                match_info['strings'].append(f"Match found (parse error: {e})")
        
        results.append(match_info)
    
    return results

def main():
    """Main function"""
    script_dir = Path(__file__).parent.absolute()
    yara_rules_path = script_dir / 'meterpreter_detection.yar'
    
    print_header("YARA Scanner for LinProcMon Sandbox Output")
    print()
    
    # Check YARA Python module
    if not check_yara_installed():
        return 1
    
    # Check if YARA rules exist
    if not yara_rules_path.exists():
        print_error(f"YARA rules not found: {yara_rules_path}")
        return 1
    
    print_success(f"YARA rules: {yara_rules_path}")
    
    # Compile YARA rules
    try:
        print_info("Compiling YARA rules...")
        yara_rules = yara.compile(filepath=str(yara_rules_path))
        print_success("YARA rules compiled successfully")
    except Exception as e:
        print_error(f"Failed to compile YARA rules: {e}")
        return 1
    
    print()
    
    # Find sandbox directories
    print_info("Searching for sandbox directories...")
    sandbox_dirs = find_sandbox_directories(script_dir)
    
    if not sandbox_dirs:
        print_warning("No sandbox_* directories found")
        print_info("Run test loaders first to generate sandbox output")
        return 0
    
    print_success(f"Found {len(sandbox_dirs)} sandbox directories")
    for sdir in sandbox_dirs:
        print(f"  - {os.path.basename(sdir)}")
    print()
    
    # Scan each sandbox directory
    total_dumps = 0
    total_matches = 0
    results_by_sandbox = {}
    
    for sandbox_dir in sandbox_dirs:
        sandbox_name = os.path.basename(sandbox_dir)
        print_header(f"Scanning: {sandbox_name}")
        
        # Find memory dumps
        dump_files = find_memory_dumps(sandbox_dir)
        
        if not dump_files:
            print_warning("No memory dumps found in this sandbox")
            print()
            continue
        
        print_info(f"Found {len(dump_files)} memory dump files")
        
        sandbox_results = {
            'dumps': len(dump_files),
            'matches_by_file': {},
            'total_matches': 0,
            'rules_matched': set()
        }
        
        # Scan each dump file
        for dump_file in dump_files:
            dump_name = os.path.basename(dump_file)
            dump_size = os.path.getsize(dump_file)
            
            print(f"\n  Scanning: {dump_name} ({dump_size:,} bytes)")
            
            matches = scan_file_with_yara(yara_rules, dump_file)
            
            if matches:
                parsed_matches = parse_yara_matches(matches)
                
                if parsed_matches:
                    sandbox_results['matches_by_file'][dump_name] = parsed_matches
                    sandbox_results['total_matches'] += len(parsed_matches)
                    
                    for match in parsed_matches:
                        sandbox_results['rules_matched'].add(match['rule'])
                        print(f"    {Colors.GREEN}✓ {match['rule']}{Colors.NC}")
                        
                        # Show first few string matches
                        for i, string_match in enumerate(match['strings'][:3]):
                            print(f"      {string_match}")
                        
                        if len(match['strings']) > 3:
                            print(f"      ... and {len(match['strings']) - 3} more matches")
                else:
                    print(f"    {Colors.YELLOW}No matches{Colors.NC}")
            else:
                print(f"    {Colors.YELLOW}No matches{Colors.NC}")
        
        results_by_sandbox[sandbox_name] = sandbox_results
        total_dumps += sandbox_results['dumps']
        total_matches += sandbox_results['total_matches']
        
        print()
    
    # Print summary
    print_header("Scan Summary")
    print()
    print(f"Sandbox directories scanned: {len(sandbox_dirs)}")
    print(f"Total memory dumps scanned: {total_dumps}")
    print(f"Total YARA rule matches: {total_matches}")
    print()
    
    if total_matches > 0:
        print_success("Successfully detected meterpreter signatures in memory dumps!")
        print()
        
        # Show matches by sandbox
        print(f"{Colors.CYAN}Matches by Sandbox:{Colors.NC}")
        for sandbox_name, results in results_by_sandbox.items():
            if results['total_matches'] > 0:
                print(f"\n  {Colors.BLUE}{sandbox_name}:{Colors.NC}")
                print(f"    Dumps with matches: {len(results['matches_by_file'])}/{results['dumps']}")
                print(f"    Total matches: {results['total_matches']}")
                print(f"    Rules triggered: {', '.join(sorted(results['rules_matched']))}")
    else:
        print_warning("No meterpreter signatures detected")
        print()
        print("This could mean:")
        print("  1. Memory dumps don't contain the payload")
        print("  2. YARA rules need adjustment")
        print("  3. Test loaders need to run longer")
    
    print()
    print_info("For detailed analysis, run:")
    print(f"  python3 yara_scan_sandbox.py")
    print("  or use yara-python API directly")
    
    return 0 if total_matches > 0 else 1

if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        print_warning("Scan interrupted by user")
        sys.exit(130)
