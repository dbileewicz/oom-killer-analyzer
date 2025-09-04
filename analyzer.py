#!/usr/bin/env python3
"""
OOM Killer Log Analyzer
Comprehensive tool for analyzing Linux OOM-killer dumps
"""

import re
import sys
import argparse
import json
from datetime import datetime
from collections import defaultdict, namedtuple
from typing import Dict, List, Tuple, Optional

# Data structures
ProcessInfo = namedtuple('ProcessInfo', [
    'pid', 'uid', 'tgid', 'total_vm', 'rss', 'pgtables_bytes', 
    'swapents', 'oom_score_adj', 'name'
])

MemoryInfo = namedtuple('MemoryInfo', [
    'active_anon', 'inactive_anon', 'active_file', 'inactive_file',
    'unevictable', 'dirty', 'writeback', 'slab_reclaimable',
    'slab_unreclaimable', 'mapped', 'shmem', 'pagetables',
    'free', 'free_pcp'
])

NodeInfo = namedtuple('NodeInfo', [
    'node_id', 'zone_type', 'free', 'min_pages', 'low_pages', 'high_pages',
    'active_anon', 'inactive_anon', 'active_file', 'inactive_file',
    'unevictable', 'present', 'managed'
])

class OOMAnalyzer:
    def __init__(self):
        self.events = []
        self.current_event = {}
        
    def parse_log_file(self, filename: str) -> List[Dict]:
        """Parse OOM killer log file and extract all events"""
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        return self.parse_log_content(content)
    
    def parse_log_content(self, content: str) -> List[Dict]:
        """Parse OOM killer log content"""
        lines = content.strip().split('\n')
        
        for line in lines:
            self._process_line(line)
        
        # Finalize last event if exists
        if self.current_event:
            self.events.append(self.current_event.copy())
        
        return self.events
    
    def _process_line(self, line: str):
        """Process a single log line"""
        # Extract timestamp and message
        timestamp_match = re.match(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+-]\d{2}:\d{2})', line)
        if timestamp_match:
            timestamp = timestamp_match.group(1)
        else:
            timestamp = None
        
        # Check for OOM killer invocation
        if 'invoked oom-killer' in line:
            # Start new event
            if self.current_event:
                self.events.append(self.current_event.copy())
            
            self.current_event = {
                'timestamp': timestamp,
                'hostname': self._extract_hostname(line),
                'trigger_info': self._parse_oom_trigger(line),
                'processes': [],
                'memory_info': {},
                'node_info': [],
                'killed_process': {},
                'hardware_info': {},
                'call_trace': []
            }
        
        elif self.current_event:
            # Parse different sections of OOM dump
            if 'Hardware name:' in line:
                self.current_event['hardware_info'] = self._parse_hardware_info(line)
            elif 'Call Trace:' in line:
                self.current_event['call_trace'] = []
            elif line.strip().startswith(']') and 'Mem-Info:' in line:
                pass  # Mem-Info header
            elif self._is_memory_stats_line(line):
                self._parse_memory_stats(line)
            elif self._is_node_info_line(line):
                self._parse_node_info(line)
            elif self._is_process_list_header(line):
                pass  # Process list header
            elif self._is_process_line(line):
                self._parse_process_line(line)
            elif 'Out of memory: Killed process' in line:
                self.current_event['killed_process'] = self._parse_killed_process(line)
            elif self._is_call_trace_line(line):
                self.current_event['call_trace'].append(self._clean_trace_line(line))
    
    def _extract_hostname(self, line: str) -> str:
        """Extract hostname from log line"""
        match = re.search(r'\s+(\w+)\s+kernel:', line)
        return match.group(1) if match else 'unknown'
    
    def _parse_oom_trigger(self, line: str) -> Dict:
        """Parse OOM trigger information"""
        info = {}
        
        # Extract gfp_mask
        gfp_match = re.search(r'gfp_mask=([^,\)]+)', line)
        if gfp_match:
            info['gfp_mask'] = gfp_match.group(1)
        
        # Extract order
        order_match = re.search(r'order=(\d+)', line)
        if order_match:
            info['order'] = int(order_match.group(1))
        
        # Extract oom_score_adj
        score_match = re.search(r'oom_score_adj=(-?\d+)', line)
        if score_match:
            info['oom_score_adj'] = int(score_match.group(1))
        
        return info
    
    def _parse_hardware_info(self, line: str) -> Dict:
        """Parse hardware information"""
        match = re.search(r'Hardware name:\s*(.+)', line)
        return {'hardware_name': match.group(1).strip()} if match else {}
    
    def _is_memory_stats_line(self, line: str) -> bool:
        """Check if line contains memory statistics"""
        return ('active_anon:' in line or 'Node 0 active_anon:' in line or 
                'Free swap' in line or 'Total swap' in line or 'pages RAM' in line)
    
    def _parse_memory_stats(self, line: str):
        """Parse memory statistics from various formats"""
        if 'active_anon:' in line and 'Node' not in line:
            # Global memory stats
            stats = {}
            patterns = [
                (r'active_anon:(\d+)', 'active_anon'),
                (r'inactive_anon:(\d+)', 'inactive_anon'),
                (r'active_file:(\d+)', 'active_file'),
                (r'inactive_file:(\d+)', 'inactive_file'),
                (r'unevictable:(\d+)', 'unevictable'),
                (r'dirty:(\d+)', 'dirty'),
                (r'writeback:(\d+)', 'writeback'),
                (r'slab_reclaimable:(\d+)', 'slab_reclaimable'),
                (r'slab_unreclaimable:(\d+)', 'slab_unreclaimable'),
                (r'mapped:(\d+)', 'mapped'),
                (r'shmem:(\d+)', 'shmem'),
                (r'pagetables:(\d+)', 'pagetables'),
                (r'free:(\d+)', 'free'),
                (r'free_pcp:(\d+)', 'free_pcp')
            ]
            
            for pattern, key in patterns:
                match = re.search(pattern, line)
                if match:
                    stats[key] = int(match.group(1))
            
            if stats:
                self.current_event['memory_info'].update(stats)
        
        elif 'Free swap' in line:
            match = re.search(r'Free swap\s*=\s*(\d+)kB', line)
            if match:
                self.current_event['memory_info']['free_swap_kb'] = int(match.group(1))
        
        elif 'Total swap' in line:
            match = re.search(r'Total swap\s*=\s*(\d+)kB', line)
            if match:
                self.current_event['memory_info']['total_swap_kb'] = int(match.group(1))
        
        elif 'pages RAM' in line:
            match = re.search(r'(\d+)\s+pages RAM', line)
            if match:
                self.current_event['memory_info']['total_ram_pages'] = int(match.group(1))
    
    def _is_node_info_line(self, line: str) -> bool:
        """Check if line contains node/zone information"""
        return re.search(r'Node \d+ \w+ free:', line) is not None
    
    def _parse_node_info(self, line: str):
        """Parse node/zone memory information"""
        match = re.search(r'Node (\d+) (\w+) free:(\d+)kB.*?min:(\d+)kB.*?low:(\d+)kB.*?high:(\d+)kB', line)
        if match:
            node_info = {
                'node_id': int(match.group(1)),
                'zone_type': match.group(2),
                'free_kb': int(match.group(3)),
                'min_kb': int(match.group(4)),
                'low_kb': int(match.group(5)),
                'high_kb': int(match.group(6))
            }
            
            # Extract additional memory info from the same line
            additional_patterns = [
                (r'active_anon:(\d+)kB', 'active_anon_kb'),
                (r'inactive_anon:(\d+)kB', 'inactive_anon_kb'),
                (r'present:(\d+)kB', 'present_kb'),
                (r'managed:(\d+)kB', 'managed_kb')
            ]
            
            for pattern, key in additional_patterns:
                match_add = re.search(pattern, line)
                if match_add:
                    node_info[key] = int(match_add.group(1))
            
            self.current_event['node_info'].append(node_info)
    
    def _is_process_list_header(self, line: str) -> bool:
        """Check if line is process list header"""
        return '[  pid  ]   uid  tgid total_vm      rss pgtables_bytes swapents oom_score_adj name' in line
    
    def _is_process_line(self, line: str) -> bool:
        """Check if line contains process information"""
        return re.search(r'\[\s*\d+\]', line) is not None
    
    def _parse_process_line(self, line: str):
        """Parse process information line"""
        # Pattern for process line: [  pid  ]   uid  tgid total_vm      rss pgtables_bytes swapents oom_score_adj name
        pattern = r'\[\s*(\d+)\]\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(-?\d+)\s+(.+)'
        match = re.search(pattern, line)
        
        if match:
            process_info = {
                'pid': int(match.group(1)),
                'uid': int(match.group(2)),
                'tgid': int(match.group(3)),
                'total_vm': int(match.group(4)),
                'rss': int(match.group(5)),
                'pgtables_bytes': int(match.group(6)),
                'swapents': int(match.group(7)),
                'oom_score_adj': int(match.group(8)),
                'name': match.group(9).strip()
            }
            self.current_event['processes'].append(process_info)
    
    def _parse_killed_process(self, line: str) -> Dict:
        """Parse killed process information"""
        pattern = r'Killed process (\d+) \(([^)]+)\) total-vm:(\d+)kB, anon-rss:(\d+)kB, file-rss:(\d+)kB, shmem-rss:(\d+)kB, UID:(\d+)'
        match = re.search(pattern, line)
        
        if match:
            return {
                'pid': int(match.group(1)),
                'name': match.group(2),
                'total_vm_kb': int(match.group(3)),
                'anon_rss_kb': int(match.group(4)),
                'file_rss_kb': int(match.group(5)),
                'shmem_rss_kb': int(match.group(6)),
                'uid': int(match.group(7))
            }
        return {}
    
    def _is_call_trace_line(self, line: str) -> bool:
        """Check if line is part of call trace"""
        return (self.current_event and 'call_trace' in self.current_event and 
                (line.strip().startswith(']') and ('show_stack' in line or 'dump_' in line or 
                 'oom_' in line or 'alloc_' in line or '+0x' in line)))
    
    def _clean_trace_line(self, line: str) -> str:
        """Clean and extract function name from trace line"""
        match = re.search(r'\]\s*([^+\s]+)', line)
        return match.group(1) if match else line.strip()
    
    def analyze_events(self) -> Dict:
        """Analyze all parsed OOM events and generate summary statistics"""
        if not self.events:
            return {}
        
        analysis = {
            'total_events': len(self.events),
            'time_range': self._get_time_range(),
            'most_killed_processes': self._get_most_killed_processes(),
            'memory_pressure_analysis': self._analyze_memory_pressure(),
            'process_statistics': self._analyze_process_stats(),
            'system_info': self._get_system_info(),
            'recommendations': self._generate_recommendations()
        }
        
        return analysis
    
    def _get_time_range(self) -> Dict:
        """Get time range of OOM events"""
        timestamps = [event.get('timestamp') for event in self.events if event.get('timestamp')]
        if not timestamps:
            return {}
        
        return {
            'first_event': min(timestamps),
            'last_event': max(timestamps),
            'total_events': len(timestamps)
        }
    
    def _get_most_killed_processes(self) -> List[Dict]:
        """Get statistics of most frequently killed processes"""
        killed_processes = defaultdict(int)
        process_details = {}
        
        for event in self.events:
            killed = event.get('killed_process', {})
            if killed and 'name' in killed:
                name = killed['name']
                killed_processes[name] += 1
                if name not in process_details:
                    process_details[name] = {
                        'avg_memory_mb': killed.get('total_vm_kb', 0) // 1024,
                        'avg_rss_mb': killed.get('anon_rss_kb', 0) // 1024,
                        'uid': killed.get('uid', 'unknown')
                    }
        
        result = []
        for process, count in sorted(killed_processes.items(), key=lambda x: x[1], reverse=True):
            result.append({
                'process_name': process,
                'kill_count': count,
                'details': process_details[process]
            })
        
        return result
    
    def _analyze_memory_pressure(self) -> Dict:
        """Analyze memory pressure patterns"""
        if not self.events:
            return {}
        
        memory_stats = []
        for event in self.events:
            mem_info = event.get('memory_info', {})
            if mem_info:
                memory_stats.append(mem_info)
        
        if not memory_stats:
            return {}
        
        # Calculate averages
        avg_stats = {}
        for key in memory_stats[0].keys():
            if isinstance(memory_stats[0][key], (int, float)):
                avg_stats[f'avg_{key}'] = sum(stat.get(key, 0) for stat in memory_stats) / len(memory_stats)
        
        return avg_stats
    
    def _analyze_process_stats(self) -> Dict:
        """Analyze process statistics across all events"""
        all_processes = []
        for event in self.events:
            all_processes.extend(event.get('processes', []))
        
        if not all_processes:
            return {}
        
        # Top memory consumers (by RSS - actual physical memory usage)
        top_rss = sorted(all_processes, key=lambda p: p.get('rss', 0), reverse=True)[:50]
        # Top virtual memory consumers (usually less relevant but available)
        top_memory = sorted(all_processes, key=lambda p: p.get('total_vm', 0), reverse=True)[:50]
        
        # Process name frequency
        process_names = defaultdict(int)
        for proc in all_processes:
            process_names[proc.get('name', 'unknown')] += 1
        
        return {
            'total_processes_analyzed': len(all_processes),
            'top_rss_consumers': [{'name': p.get('name'), 'rss_mb': p.get('rss', 0) // 256} for p in top_rss],
            'top_virtual_memory_consumers': [{'name': p.get('name'), 'total_vm_mb': p.get('total_vm', 0) // 256} for p in top_memory],
            'most_common_processes': dict(sorted(process_names.items(), key=lambda x: x[1], reverse=True)[:10])
        }
    
    def _get_system_info(self) -> Dict:
        """Extract system information from events"""
        if not self.events:
            return {}
        
        # Get info from first event
        first_event = self.events[0]
        
        system_info = {
            'hostname': first_event.get('hostname', 'unknown'),
            'hardware_info': first_event.get('hardware_info', {})
        }
        
        # Memory info from first event
        mem_info = first_event.get('memory_info', {})
        if 'total_ram_pages' in mem_info:
            system_info['total_ram_gb'] = (mem_info['total_ram_pages'] * 4) // (1024 * 1024)
        if 'total_swap_kb' in mem_info:
            system_info['total_swap_gb'] = mem_info['total_swap_kb'] // (1024 * 1024)
        
        return system_info
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on analysis"""
        recommendations = []
        
        if not self.events:
            return recommendations
        
        # Check frequency of OOM events
        if len(self.events) > 5:
            recommendations.append("High frequency of OOM events detected. Consider increasing system memory or investigating memory leaks.")
        
        # Check for specific process patterns
        killed_stats = self._get_most_killed_processes()
        if killed_stats:
            top_killed = killed_stats[0]
            if top_killed['kill_count'] > len(self.events) * 0.5:
                recommendations.append(f"Process '{top_killed['process_name']}' is frequently killed. Investigate memory usage patterns.")
        
        # Check swap usage
        for event in self.events:
            mem_info = event.get('memory_info', {})
            if 'total_swap_kb' in mem_info and 'free_swap_kb' in mem_info:
                if mem_info['total_swap_kb'] > 0:  # Avoid division by zero
                    swap_usage = 1 - (mem_info['free_swap_kb'] / mem_info['total_swap_kb'])
                    if swap_usage > 0.9:
                        recommendations.append("High swap usage detected. Consider adding more RAM or optimizing memory usage.")
                        break
        
        # General recommendations
        recommendations.extend([
            "Monitor memory usage patterns with tools like 'sar', 'vmstat', or 'htop'",
            "Consider implementing memory limits for containers/processes using cgroups",
            "Review and tune vm.swappiness and vm.vfs_cache_pressure kernel parameters",
            "Implement proper application memory management and garbage collection tuning"
        ])
        
        return recommendations
    
    def generate_report(self, output_format='text', top_count=10, min_memory_mb=0) -> str:
        """Generate comprehensive analysis report
        
        Args:
            output_format: 'text' or 'json'
            top_count: Number of top processes to show
            min_memory_mb: Minimum memory usage (MB) to include in top consumers
        """
        analysis = self.analyze_events()
        
        if output_format == 'json':
            return json.dumps({
                'events': self.events,
                'analysis': analysis
            }, indent=2, default=str)
        
        # Text report
        report = []
        report.append("=" * 60)
        report.append("OOM KILLER ANALYSIS REPORT")
        report.append("=" * 60)
        report.append("")
        
        # Summary
        if analysis:
            report.append(f"Total OOM Events: {analysis.get('total_events', 0)}")
            
            time_range = analysis.get('time_range', {})
            if time_range:
                report.append(f"Time Range: {time_range.get('first_event', 'N/A')} to {time_range.get('last_event', 'N/A')}")
            
            system_info = analysis.get('system_info', {})
            if system_info:
                report.append(f"Hostname: {system_info.get('hostname', 'N/A')}")
                if 'total_ram_gb' in system_info:
                    report.append(f"Total RAM: {system_info['total_ram_gb']} GB")
                if 'total_swap_gb' in system_info:
                    report.append(f"Total Swap: {system_info['total_swap_gb']} GB")
            
            report.append("")
            
            # Most killed processes
            killed_processes = analysis.get('most_killed_processes', [])
            if killed_processes:
                report.append("MOST FREQUENTLY KILLED PROCESSES:")
                report.append("-" * 40)
                for proc in killed_processes[:5]:
                    report.append(f"  {proc['process_name']}: {proc['kill_count']} times killed "
                                f"(avg {proc['details']['avg_memory_mb']} MB)")
                report.append("")
            
            # Process statistics
            proc_stats = analysis.get('process_statistics', {})
            if proc_stats and 'top_rss_consumers' in proc_stats:
                if group_by_name:
                    # Group processes by name and sum their memory usage
                    process_groups = defaultdict(lambda: {'total_rss': 0, 'count': 0, 'pids': []})
                    for proc in proc_stats['top_rss_consumers']:
                        name = proc['name']
                        rss_mb = proc['rss_mb']
                        process_groups[name]['total_rss'] += rss_mb
                        process_groups[name]['count'] += 1
                        # We don't have PIDs in the current structure, but we can add count
                    
                    # Filter and sort grouped processes
                    filtered_groups = [
                        {
                            'name': name, 
                            'total_rss_mb': data['total_rss'], 
                            'process_count': data['count'],
                            'avg_rss_mb': data['total_rss'] / data['count']
                        }
                        for name, data in process_groups.items() 
                        if data['total_rss'] >= min_memory_mb
                    ]
                    filtered_groups.sort(key=lambda x: x['total_rss_mb'], reverse=True)
                    filtered_groups = filtered_groups[:top_count]
                    
                    if filtered_groups:
                        report.append(f"TOP MEMORY CONSUMERS BY PROCESS NAME - Showing {len(filtered_groups)} process types")
                        if min_memory_mb > 0:
                            report.append(f"(Minimum {min_memory_mb} MB total)")
                        report.append("-" * 60)
                        for i, proc in enumerate(filtered_groups, 1):
                            report.append(f"  {i:2}. {proc['name']}: {proc['total_rss_mb']:,} MB "
                                        f"({proc['process_count']} processes, avg {proc['avg_rss_mb']:.1f} MB each)")
                        
                        total_memory = sum(proc['total_rss_mb'] for proc in filtered_groups)
                        total_processes = sum(proc['process_count'] for proc in filtered_groups)
                        report.append(f"\n  Summary: {len(filtered_groups)} process types, {total_processes} total processes, "
                                    f"Total: {total_memory:,} MB")
                        report.append("")
                    else:
                        report.append(f"No process groups found consuming more than {min_memory_mb} MB total")
                        report.append("")
                else:
                    # Original individual process listing
                    filtered_consumers = [
                        proc for proc in proc_stats['top_rss_consumers'] 
                        if proc['rss_mb'] >= min_memory_mb
                    ][:top_count]
                    
                    if filtered_consumers:
                        report.append(f"TOP ACTUAL MEMORY CONSUMERS (RSS) - Showing {len(filtered_consumers)} processes")
                        if min_memory_mb > 0:
                            report.append(f"(Minimum {min_memory_mb} MB)")
                        report.append("-" * 50)
                        for i, proc in enumerate(filtered_consumers, 1):
                            report.append(f"  {i:2}. {proc['name']}: {proc['rss_mb']:,} MB")
                        
                        # Show summary statistics
                        total_memory = sum(proc['rss_mb'] for proc in filtered_consumers)
                        avg_memory = total_memory / len(filtered_consumers) if filtered_consumers else 0
                        report.append(f"\n  Summary: {len(filtered_consumers)} processes, "
                                    f"Total: {total_memory:,} MB, Average: {avg_memory:.1f} MB")
                        report.append("")
                    else:
                        report.append(f"No processes found consuming more than {min_memory_mb} MB")
                        report.append("")
            
            # Recommendations
            recommendations = analysis.get('recommendations', [])
            if recommendations:
                report.append("RECOMMENDATIONS:")
                report.append("-" * 40)
                for i, rec in enumerate(recommendations, 1):
                    report.append(f"  {i}. {rec}")
                report.append("")
        
        # Detailed events
        report.append("DETAILED OOM EVENTS:")
        report.append("-" * 40)
        for i, event in enumerate(self.events, 1):
            report.append(f"Event #{i}:")
            report.append(f"  Timestamp: {event.get('timestamp', 'N/A')}")
            report.append(f"  Hostname: {event.get('hostname', 'N/A')}")
            
            killed = event.get('killed_process', {})
            if killed:
                report.append(f"  Killed Process: {killed.get('name', 'N/A')} (PID: {killed.get('pid', 'N/A')})")
                report.append(f"  Memory Usage: {killed.get('total_vm_kb', 0) // 1024} MB total, "
                            f"{killed.get('anon_rss_kb', 0) // 1024} MB RSS")
            
            trigger = event.get('trigger_info', {})
            if trigger:
                report.append(f"  Trigger: gfp_mask={trigger.get('gfp_mask', 'N/A')}, "
                            f"order={trigger.get('order', 'N/A')}")
            
            mem_info = event.get('memory_info', {})
            if 'free' in mem_info:
                report.append(f"  Free Memory: {mem_info['free'] * 4 // 1024} MB")
            
            report.append("")
        
        return "\n".join(report)

def main():
    parser = argparse.ArgumentParser(description='Analyze OOM Killer logs')
    parser.add_argument('logfile', help='Path to log file containing OOM events')
    parser.add_argument('--format', choices=['text', 'json'], default='text',
                       help='Output format (default: text)')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--top-count', type=int, default=10,
                       help='Number of top memory consumers to show (default: 10)')
    parser.add_argument('--min-memory', type=int, default=0,
                       help='Minimum memory usage in MB to include in top consumers (default: 0)')
    
    args = parser.parse_args()
    
    try:
        analyzer = OOMAnalyzer()
        analyzer.parse_log_file(args.logfile)
        report = analyzer.generate_report(args.format, args.top_count, args.min_memory)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"Analysis written to {args.output}")
        else:
            print(report)
            
    except FileNotFoundError:
        print(f"Error: File '{args.logfile}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error analyzing log: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
