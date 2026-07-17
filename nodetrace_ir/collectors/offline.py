from __future__ import annotations

from nodetrace_ir.contracts import CollectionContext, GapDraft, utc_now

from ._common import cancelled_gap, finish, new_result


class OfflineCoverageCollector:
    """Record volatile evidence that a mounted Windows volume cannot provide.

    This collector deliberately does not inspect the WinPE host.  Its gaps make
    the boundary between the mounted target and the currently running recovery
    environment explicit in every offline collection run.
    """

    name = "offline_coverage"
    display_name = "Offline target coverage boundaries"
    supports_offline = True

    def collect(self, context: CollectionContext):
        started_at = utc_now()
        result = new_result(self.name, started_at)
        if context.cancel_event.is_set():
            result.gaps.append(cancelled_gap(self.name))
            return finish(result)

        offline_root = str(context.options.get("offline_root") or "")
        result.gaps.extend(
            [
                GapDraft(
                    collector=self.name,
                    source="Offline target live processes",
                    reason=(
                        "The target Windows installation is not running; NodeTrace IR did not "
                        "collect processes from the WinPE host"
                    ),
                    impact="Processes that were active at shutdown or compromise time are unavailable",
                    recommendation=(
                        "Correlate preserved event logs, Prefetch and a separately acquired memory image"
                    ),
                ),
                GapDraft(
                    collector=self.name,
                    source="Offline target network state",
                    reason=(
                        "Active sockets, owning processes and the volatile DNS cache do not exist in "
                        "the mounted filesystem; WinPE network state was intentionally excluded"
                    ),
                    impact="Live command-and-control connections and volatile DNS entries are unavailable",
                    recommendation=(
                        "Use a memory image, upstream firewall/DNS logs or a live-response capture from "
                        "the affected OS"
                    ),
                ),
                GapDraft(
                    collector=self.name,
                    source="Offline target volatile state",
                    reason="A mounted Windows volume contains persistent files, not volatile memory state",
                    impact=(
                        "In-memory-only malware, injected code, handles, tokens and unsaved runtime state "
                        "cannot be determined"
                    ),
                    recommendation="Acquire and analyze RAM before shutdown whenever incident conditions permit",
                ),
            ]
        )
        result.raw_payload = {
            "target_mode": "offline",
            "offline_root": offline_root,
            "winpe_host_telemetry_collected": False,
            "unavailable_sources": ["live_processes", "network", "volatile_state"],
        }
        return finish(result)


__all__ = ["OfflineCoverageCollector"]
