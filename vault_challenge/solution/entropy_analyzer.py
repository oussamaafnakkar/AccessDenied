#!/usr/bin/env python3
"""
Entropy Analyzer for Binary Files
Detects packing/encryption via entropy analysis

Author: Oussama Afnakkar - Secure Byte Chronicles
Usage: python3 entropy_analyzer.py <binary_file>
"""

import sys
import math
from collections import Counter
import matplotlib.pyplot as plt
import numpy as np


def calculate_entropy(data):
    """Calculate Shannon entropy in bits/byte"""
    if not data:
        return 0
    
    counter = Counter(data)
    length = len(data)
    
    entropy = 0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy


def analyze_file_entropy(filename, block_size=256):
    """Analyze entropy across file blocks"""
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print(f"[!] Error: File '{filename}' not found")
        sys.exit(1)
    
    # Overall entropy
    total_entropy = calculate_entropy(data)
    
    # Block-by-block entropy
    entropies = []
    positions = []
    
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        if len(block) == block_size:
            entropy = calculate_entropy(block)
            entropies.append(entropy)
            positions.append(i)
    
    return data, total_entropy, positions, entropies


def interpret_entropy(entropy):
    """Interpret entropy value"""
    if entropy < 3.0:
        return "Very Low (Plaintext/Repetitive)", "🟢"
    elif entropy < 6.0:
        return "Normal (Typical Executable)", "🟡"
    elif entropy < 7.5:
        return "High (Possibly Packed)", "🟠"
    else:
        return "Very High (Packed/Encrypted)", "🔴"


def plot_entropy_graph(filename, positions, entropies, total_entropy):
    """Generate entropy visualization"""
    plt.figure(figsize=(14, 6))
    
    # Plot entropy per block
    plt.plot(positions, entropies, linewidth=0.8, color='#2E86AB')
    
    # Add threshold lines
    plt.axhline(y=6.0, color='orange', linestyle='--', 
                linewidth=1.5, label='Packing Threshold (6.0)', alpha=0.7)
    plt.axhline(y=7.5, color='red', linestyle='--', 
                linewidth=1.5, label='High Packing (7.5)', alpha=0.7)
    
    # Add average line
    plt.axhline(y=total_entropy, color='green', linestyle='-', 
                linewidth=2, label=f'Average Entropy ({total_entropy:.2f})', alpha=0.8)
    
    # Styling
    plt.xlabel('File Offset (bytes)', fontsize=12, fontweight='bold')
    plt.ylabel('Entropy (bits/byte)', fontsize=12, fontweight='bold')
    plt.title(f'Entropy Analysis: {filename}', fontsize=14, fontweight='bold')
    plt.legend(loc='upper right', fontsize=10)
    plt.grid(True, alpha=0.3, linestyle=':', linewidth=0.5)
    plt.ylim(0, 8.5)
    
    # Save
    output_file = f"{filename}_entropy_graph.png"
    plt.tight_layout()
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    print(f"\n[+] Graph saved: {output_file}")
    
    # Display
    plt.show()


def display_report(filename, total_entropy, data_size, entropies):
    """Display analysis report"""
    interpretation, emoji = interpret_entropy(total_entropy)
    
    print("\n" + "=" * 60)
    print("  ENTROPY ANALYSIS REPORT")
    print("=" * 60)
    print(f"\n  File: {filename}")
    print(f"  Size: {data_size:,} bytes ({data_size / 1024:.2f} KB)")
    print(f"\n  Overall Entropy: {total_entropy:.2f} bits/byte")
    print(f"   Status: {emoji} {interpretation}")
    
    # Statistics
    if entropies:
        avg_block = np.mean(entropies)
        max_block = np.max(entropies)
        min_block = np.min(entropies)
        std_block = np.std(entropies)
        
        print(f"\n  Block Statistics (256-byte blocks):")
        print(f"   Average: {avg_block:.2f}")
        print(f"   Maximum: {max_block:.2f}")
        print(f"   Minimum: {min_block:.2f}")
        print(f"   Std Dev: {std_block:.2f}")
    
    # Assessment
    print(f"\n  Assessment:")
    if total_entropy < 3.0:
        print("     File appears to be plaintext or highly repetitive")
        print("   → Likely: Text file, log, or uncompressed data")
    elif total_entropy < 6.0:
        print("     Normal entropy for compiled executable")
        print("   → Likely: Unpacked binary with mixed code/data")
    elif total_entropy < 7.5:
        print("     Elevated entropy - possibly packed")
        print("   → Action: Check for packer signatures (UPX, ASPack)")
        print("   → Tools: 'strings', Detect It Easy, PEiD")
    else:
        print("     Very high entropy - strong packing/encryption")
        print("   → Action: Unpack before analysis")
        print("   → Tools: UPX unpacker, manual OEP finding")
    
    print("\n" + "=" * 60 + "\n")


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 entropy_analyzer.py <binary_file>")
        print("\nExample:")
        print("  python3 entropy_analyzer.py vault_challenge.exe")
        sys.exit(1)
    
    filename = sys.argv[1]
    
    print("\n  Analyzing file entropy...")
    
    # Analyze
    data, total_entropy, positions, entropies = analyze_file_entropy(filename)
    
    # Display report
    display_report(filename, total_entropy, len(data), entropies)
    
    # Generate graph
    try:
        plot_entropy_graph(filename, positions, entropies, total_entropy)
    except Exception as e:
        print(f"[!] Could not generate graph: {e}")
        print("    (matplotlib may not be installed)")


if __name__ == "__main__":
    main()
