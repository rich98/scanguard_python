import cProfile
import pstats
import os

# Set full path to your script
target_script = r"(Drive):\your path to file\Scan_Guard_Dog_Pro_0.4.114_Beta.py"
profile_output = "scan_guard_profile.prof"

# Prepare global context for exec
global_vars = {
    "__file__": target_script,
    "__name__": "__main__",
    "__package__": None,
}

# Run profiling with injected globals
cProfile.runctx(
    open(target_script).read(),
    globals=global_vars,
    locals=None,
    filename=profile_output
)

# Generate readable report
with open("scan_guard_profile_report.txt", "w") as f:
    stats = pstats.Stats(profile_output, stream=f)
    stats.strip_dirs()
    stats.sort_stats("cumulative")  # or 'time'
    stats.print_stats(30)


