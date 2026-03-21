"""
Sprint 1 — ETL Pipeline CLI Runner
=====================================
Top-level entry point that orchestrates the full pipeline:

  Step 1  ingest    — parse CERT CSVs → normalised Parquet files
  Step 2  transform — aggregate daily risk snapshots
  Step 3  seed      — write to Neon Postgres (optional)

Usage examples:
  # Full run (ingest + transform + seed)
  python -m pipeline.run_etl --all

  # Ingest only (produces dataset/processed/normalized/*.parquet)
  python -m pipeline.run_etl --ingest

  # Transform only (requires ingest already done)
  python -m pipeline.run_etl --transform

  # Seed Postgres from existing Parquet (requires transform done)
  python -m pipeline.run_etl --seed

  # Seed a limited batch (good for dev/CI)
  python -m pipeline.run_etl --seed --limit 10000

  # Full run, dry-seed only (no DB writes)
  python -m pipeline.run_etl --all --dry-run

  # Process a single source for quick iteration
  python -m pipeline.run_etl --ingest --sources logon email
"""

import argparse
import json
import logging
import sys
import time
from pathlib import Path

logger = logging.getLogger(__name__)


def _configure_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stdout,
    )


def step_ingest(dataset_dir: Path, output_dir: Path, sources: list[str]) -> dict:
    from pipeline.ingest import run_pipeline
    logger.info("━━━ Step 1: Ingest ━━━")
    t0 = time.perf_counter()
    stats = run_pipeline(
        dataset_dir=dataset_dir,
        output_dir=output_dir / "normalized",
        sources=sources,
    )
    elapsed = time.perf_counter() - t0
    logger.info("Ingest complete in %.1fs", elapsed)
    return {"step": "ingest", "elapsed_s": round(elapsed, 1), "sources": stats}


def step_transform(output_dir: Path, ground_truth_path: Path | None) -> dict:
    from pipeline.ingest import load_ground_truth
    from pipeline.transform import build_aggregates
    logger.info("━━━ Step 2: Transform ━━━")
    t0 = time.perf_counter()

    gt_df = None
    if ground_truth_path and ground_truth_path.exists():
        gt_df = load_ground_truth(ground_truth_path)
        logger.info("Ground truth loaded: %d labelled users.", len(gt_df))

    daily_df, profiles_df = build_aggregates(
        normalized_dir=output_dir / "normalized",
        output_dir=output_dir / "aggregated",
        ground_truth_df=gt_df,
    )
    elapsed = time.perf_counter() - t0
    logger.info("Transform complete in %.1fs", elapsed)
    return {
        "step": "transform",
        "elapsed_s": round(elapsed, 1),
        "daily_rows": len(daily_df),
        "user_profiles": len(profiles_df),
        "malicious_users": int((profiles_df["is_malicious"] == 1).sum()),
    }


def step_seed(output_dir: Path, limit: int | None, dry_run: bool, database_url: str | None) -> dict:
    from pipeline.seed_postgres import seed
    logger.info("━━━ Step 3: Seed Postgres ━━━")
    t0 = time.perf_counter()
    stats = seed(
        limit=limit,
        dry_run=dry_run,
        database_url=database_url,
        normalized_dir=output_dir / "normalized",
        aggregated_dir=output_dir / "aggregated",
    )
    elapsed = time.perf_counter() - t0
    stats["elapsed_s"] = round(elapsed, 1)
    logger.info("Seed complete in %.1fs", elapsed)
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(
        description="NPCI PS3 — CERT ETL Pipeline Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Step selectors
    steps = parser.add_argument_group("Steps (choose one or more, or --all)")
    steps.add_argument("--all", action="store_true", help="Run ingest + transform + seed")
    steps.add_argument("--ingest", action="store_true", help="Parse CERT CSVs → Parquet")
    steps.add_argument("--transform", action="store_true", help="Aggregate daily snapshots")
    steps.add_argument("--seed", action="store_true", help="Write to Neon Postgres")

    # Paths
    paths = parser.add_argument_group("Paths")
    paths.add_argument("--dataset-dir", type=Path,
                       default=Path(__file__).parent.parent.parent / "dataset",
                       help="Directory containing raw CERT CSV files.")
    paths.add_argument("--output-dir", type=Path,
                       default=Path(__file__).parent.parent.parent / "dataset" / "processed",
                       help="Output directory for Parquet files.")
    paths.add_argument("--ground-truth", type=Path, default=None,
                       help="Path to answers/insiders.csv for ground truth labels.")

    # Ingestion options
    ingest_opts = parser.add_argument_group("Ingestion options")
    ingest_opts.add_argument("--sources", nargs="+",
                             choices=["logon", "device", "file", "email", "http"],
                             default=["logon", "device", "file", "email", "http"],
                             help="Subset of sources to ingest (default: all five).")

    # Seed options
    seed_opts = parser.add_argument_group("Seed options")
    seed_opts.add_argument("--limit", type=int, default=None,
                           help="Limit ActivityLog inserts (useful for dev).")
    seed_opts.add_argument("--dry-run", action="store_true",
                           help="Validate seed rows without writing to DB.")
    seed_opts.add_argument("--database-url", type=str, default=None,
                           help="Override DATABASE_URL environment variable.")

    # Misc
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()
    _configure_logging(args.verbose)

    # Determine which steps to run
    run_ingest    = args.all or args.ingest
    run_transform = args.all or args.transform
    run_seed      = args.all or args.seed

    if not (run_ingest or run_transform or run_seed):
        parser.print_help()
        sys.exit(1)

    # Resolve ground truth path
    gt_path = args.ground_truth or (args.dataset_dir / "answers" / "insiders.csv")

    summary = {}

    if run_ingest:
        summary["ingest"] = step_ingest(args.dataset_dir, args.output_dir, args.sources)

    if run_transform:
        summary["transform"] = step_transform(args.output_dir, gt_path)

    if run_seed:
        summary["seed"] = step_seed(
            args.output_dir, args.limit, args.dry_run, args.database_url
        )

    print("\n" + "=" * 60)
    print("ETL PIPELINE SUMMARY")
    print("=" * 60)
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
