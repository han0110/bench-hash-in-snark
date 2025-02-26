import sys

package_hashes = [
    ("binius", ["keccak", "vision"]),
    ("expander", ["keccak", "poseidon"]),
    ("hashcaster", ["keccak"]),
    ("plonky3", ["blake3", "keccak", "poseidon2"]),
    ("stwo", ["blake2s", "poseidon2"]),
]

try:
    num_threads = sys.argv[1]
except Exception:
    num_threads = "4"

print("")
for package, hashes in package_hashes:
    print(f"<!-- {package} -->")
    print("")
    print("| `hash` | `perm` | `time` | `throughput` | `proof_size` | `peak_mem` |")
    print("| - | - | - | - | - | - |")
    for idx, hash in enumerate(hashes):
        if idx != 0:
            print("| | | | | | |")
        rows = []
        for log_permutations in range(10, 21):
            try:
                path = f"{package}/report/t{num_threads}_{hash}_lp{log_permutations}"
                lines = open(path).readlines()
                if len(lines) != 4:
                    raise Exception
                report = [line.strip().split(": ")[1] for line in lines]
            except Exception:
                report = ["-", "-", "-", "-"]
            rows.append((hash, log_permutations, *report))
        for hash, log_permutations, time, throughput, proof_size, peak_mem in rows:
            print(
                f"| `{hash}` | <code>2<sup>{log_permutations}</sup></code> | `{time}` | `{throughput}` | `{proof_size}` | `{peak_mem}` |"
            )
    print("")
