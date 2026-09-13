"""
Task 3: Performance Comparison
Runs openssl speed benchmarks for AES and RSA, parses results, and generates plots.
"""
import subprocess
import re
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


def run_openssl_speed(algorithm, seconds=1):
    cmd = f"openssl speed -seconds {seconds} {algorithm}"
    print(f"Running: {cmd}")
    result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=300)
    return result.stdout + result.stderr


def run_openssl_speed_rsa(seconds=1):
    """Run RSA benchmarks one key size at a time to avoid long waits."""
    all_output = ""
    for bits in [512, 1024, 2048, 4096]:
        cmd = f"openssl speed -seconds {seconds} rsa{bits}"
        print(f"Running: {cmd}")
        result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=60)
        output = result.stdout + result.stderr
        all_output += output + "\n"
        print(f"  Done with RSA-{bits}")
    return all_output


def parse_aes_results(output):
    """Parse AES throughput results from openssl speed output."""
    results = {}
    block_sizes = [16, 64, 256, 1024, 8192, 16384]

    for line in output.split('\n'):
        for key_size in [128, 192, 256]:
            pattern = rf'aes-{key_size}-cbc\s+'
            match = re.match(pattern, line)
            if match:
                nums = re.findall(r'([\d.]+)k', line)
                if len(nums) >= 6:
                    results[key_size] = {}
                    for i, bs in enumerate(block_sizes):
                        results[key_size][bs] = float(nums[i])
    return results


def parse_rsa_results(output):
    """Parse RSA sign/verify throughput results from openssl speed output."""
    results = {}
    for line in output.split('\n'):
        match = re.match(r'\s*rsa\s+(\d+)\s+bits\s+([\d.]+)s\s+([\d.]+)s\s+([\d.]+)\s+([\d.]+)', line)
        if match:
            bits = int(match.group(1))
            results[bits] = {
                'sign_per_sec': float(match.group(4)),
                'verify_per_sec': float(match.group(5)),
            }
    return results


def plot_aes_results(results):
    plt.figure(figsize=(10, 6))
    for key_size, data in sorted(results.items()):
        sizes = sorted(data.keys())
        throughputs = [data[s] / 1000 for s in sizes]  # kB/s -> MB/s
        plt.plot(sizes, throughputs, marker='o', label=f'AES-{key_size}-CBC')

    plt.xlabel('Block Size (bytes)')
    plt.ylabel('Throughput (MB/s)')
    plt.title('AES Throughput: Block Size vs. Throughput for Various Key Sizes')
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.xscale('log', base=2)
    plt.tight_layout()
    plt.savefig('aes_throughput.png', dpi=150)
    print("Saved aes_throughput.png")
    plt.close()


def plot_rsa_results(results):
    plt.figure(figsize=(10, 6))
    key_sizes = sorted(results.keys())
    sign_rates = [results[k]['sign_per_sec'] for k in key_sizes]
    verify_rates = [results[k]['verify_per_sec'] for k in key_sizes]

    x_labels = [str(k) for k in key_sizes]
    x_pos = range(len(key_sizes))

    plt.bar([p - 0.2 for p in x_pos], sign_rates, 0.4, label='Sign', color='steelblue')
    plt.bar([p + 0.2 for p in x_pos], verify_rates, 0.4, label='Verify', color='coral')

    plt.xlabel('RSA Key Size (bits)')
    plt.ylabel('Operations per Second')
    plt.title('RSA Throughput: Key Size vs. Operations per Second')
    plt.xticks(list(x_pos), x_labels)
    plt.legend()
    plt.grid(True, alpha=0.3, axis='y')
    plt.yscale('log')
    plt.tight_layout()
    plt.savefig('rsa_throughput.png', dpi=150)
    print("Saved rsa_throughput.png")
    plt.close()


if __name__ == '__main__':
    print("=" * 60)
    print("Task 3: Performance Comparison - AES vs RSA")
    print("=" * 60)

    print("\n--- AES Benchmark ---")
    aes_output = run_openssl_speed("aes")
    print(aes_output)

    print("\n--- RSA Benchmark ---")
    rsa_output = run_openssl_speed_rsa(seconds=1)
    print(rsa_output)

    aes_results = parse_aes_results(aes_output)
    rsa_results = parse_rsa_results(rsa_output)

    print(f"\nParsed AES results: {aes_results}")
    print(f"Parsed RSA results: {rsa_results}")

    if aes_results:
        plot_aes_results(aes_results)
    else:
        print("WARNING: Could not parse AES results")

    if rsa_results:
        plot_rsa_results(rsa_results)
    else:
        print("WARNING: Could not parse RSA results")
