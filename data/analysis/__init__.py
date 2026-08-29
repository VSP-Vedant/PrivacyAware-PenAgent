"""Data analysis utilities for PrivacyAware-PenAgent.

Provides three sub-modules:

- **aggregator**: Loads run metrics, computes aggregates, per-target
  breakdowns, and comparison tables against baselines.
- **variance**: Statistical variance analysis with mean ± std, standard
  error, and 95% confidence intervals.
- **charts**: Matplotlib chart generation (SR/PR bars, routing pie,
  TTFS bars, exploit efficiency stacked bars).

Owner: Parth (Member D) — Week 23–28 deliverable
"""

from data.analysis.ablation import (
    aggregate_by_condition,
    build_ablation_table,
    generate_ablation_charts,
)
from data.analysis.aggregator import (
    build_comparison_table,
    compute_aggregate_stats,
    load_all_metrics,
    per_target_breakdown,
    save_aggregate_report,
)
from data.analysis.charts import (
    generate_all_charts,
    generate_exploit_efficiency_chart,
    generate_routing_pie_chart,
    generate_sr_pr_bar_chart,
    generate_ttfs_bar_chart,
)
from data.analysis.variance import (
    format_variance_table,
    success_rate_ci,
    variance_summary,
)

__all__ = [
    "aggregate_by_condition",
    "build_ablation_table",
    "build_comparison_table",
    "compute_aggregate_stats",
    "format_variance_table",
    "generate_ablation_charts",
    "generate_all_charts",
    "generate_exploit_efficiency_chart",
    "generate_routing_pie_chart",
    "generate_sr_pr_bar_chart",
    "generate_ttfs_bar_chart",
    "load_all_metrics",
    "per_target_breakdown",
    "save_aggregate_report",
    "success_rate_ci",
    "variance_summary",
]
