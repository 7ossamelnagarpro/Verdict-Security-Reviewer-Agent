# Configuration

Runtime scanner and policy configuration will be added here in later
implementation stages. The current trusted default policy is represented by the
typed `ProfilerPolicy` model, and the pinned offline scanner capability registry
is in `src/security_reviewer_v2/profiler/registry.py`.

Configuration files inside a project being profiled are treated as untrusted
project data and cannot silently disable system scans.
