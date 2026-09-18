"""Queries over stored analyses: history, velocity, cross-case correlation and campaign graph."""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta

from app.db import Database
from app.schemas import (
    AnalysisListItem,
    AnalysisPage,
    AnalysisResult,
    CampaignGraph,
    GraphEdge,
    GraphNode,
    RelatedCase,
    SharedIndicator,
    Stats,
    VelocityWindow,
)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


class Repository:
    def __init__(self, db: Database) -> None:
        self.db = db

    # --- writes ------------------------------------------------------------

    def save(
        self, result: AnalysisResult, sent_at: datetime, sender_key: str, indicators: set[tuple[str, str]]
    ) -> None:
        payload = result.model_dump_json(by_alias=True)
        geo = result.origin.geo
        with self.db.connect() as conn:
            conn.execute(
                "INSERT INTO analyses(id, created_at, sent_at, sha256, subject, from_address, from_domain, sender_key,"
                " origin_ip, country, asn, score, level, verdict, result_json)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    result.id,
                    _iso(result.created_at),
                    _iso(sent_at),
                    result.sha256,
                    result.summary.subject,
                    result.summary.from_.address,
                    result.summary.from_.domain,
                    sender_key,
                    result.origin.ip,
                    # ISO code, not the name: names differ by provider ("India" vs "IN") and would split
                    # the dashboard counts. A masked origin is the provider's server, so it gets none.
                    (geo.country_code or "").upper() or None if geo and not result.origin.webmail_masked else None,
                    result.origin.asn,
                    result.risk.score,
                    result.risk.level,
                    result.risk.verdict,
                    payload,
                ),
            )
            conn.executemany(
                "INSERT OR IGNORE INTO indicators(analysis_id, kind, value) VALUES (?, ?, ?)",
                [(result.id, kind, value) for kind, value in indicators],
            )

    def delete(self, analysis_id: str) -> str | None:
        with self.db.connect() as conn:
            row = conn.execute("SELECT sha256 FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
            if row:
                conn.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))
        return row["sha256"] if row else None

    def sha_in_use(self, sha256: str) -> bool:
        with self.db.connect() as conn:
            return conn.execute("SELECT 1 FROM analyses WHERE sha256 = ? LIMIT 1", (sha256,)).fetchone() is not None

    # --- reads -------------------------------------------------------------

    def get(self, analysis_id: str) -> AnalysisResult | None:
        with self.db.connect() as conn:
            row = conn.execute("SELECT result_json FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
        return AnalysisResult.model_validate_json(row["result_json"]) if row else None

    def list(
        self, query: str = "", level: str = "", verdict: str = "", limit: int = 50, offset: int = 0
    ) -> AnalysisPage:
        clauses, params = [], []
        if query:
            like = f"%{query.lower()}%"
            clauses.append(
                "(lower(subject) LIKE ? OR lower(from_address) LIKE ? OR origin_ip LIKE ? OR sha256 LIKE ?"
                " OR id IN (SELECT analysis_id FROM indicators WHERE value LIKE ?))"
            )
            params += [like, like, like, like, like]
        if level:
            clauses.append("level = ?")
            params.append(level)
        if verdict:
            clauses.append("verdict = ?")
            params.append(verdict)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.db.connect() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM analyses {where}", params).fetchone()[0]
            rows = conn.execute(
                f"SELECT id, created_at, subject, from_address, from_domain, origin_ip, country, score, level, verdict"
                f" FROM analyses {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
        return AnalysisPage(items=[AnalysisListItem(**dict(row)) for row in rows], total=total)

    # --- behaviour ---------------------------------------------------------

    def velocity(self, column: str, value: str | None, reference: datetime, key: str) -> VelocityWindow | None:
        """Trailing message counts for one sender attribute at `reference`, including the current message.

        The z-score compares the current hour against the hourly counts of the preceding 7 days.
        """
        if not value or column not in ("origin_ip", "sender_key"):
            return None
        ref = reference.astimezone(UTC)
        week_start = ref - timedelta(days=7)
        with self.db.connect() as conn:
            rows = conn.execute(
                f"SELECT sent_at FROM analyses WHERE {column} = ? AND sent_at >= ? AND sent_at <= ?",
                (value, _iso(week_start), _iso(ref)),
            ).fetchall()
        times = [datetime.fromisoformat(r["sent_at"]) for r in rows]
        count_5m = 1 + sum(1 for t in times if ref - t <= timedelta(minutes=5))
        count_1h = 1 + sum(1 for t in times if ref - t <= timedelta(hours=1))

        history = [t for t in times if t < ref - timedelta(hours=1)]
        zscore = None
        if history:
            buckets = [0] * (7 * 24 - 1)
            for t in history:
                slot = int((ref - t).total_seconds() // 3600) - 1
                if 0 <= slot < len(buckets):
                    buckets[slot] += 1
            mean = statistics.fmean(buckets)
            stdev = statistics.pstdev(buckets) or 1.0  # a flat history would otherwise divide by zero
            zscore = round((count_1h - mean) / stdev, 2)
        burst = count_5m >= 3 or (count_1h >= 5 and (zscore is None or zscore >= 3))
        return VelocityWindow(
            key=key,
            value=value,
            count_5m=count_5m,
            count_1h=count_1h,
            zscore=zscore,
            history_hours=len({int((ref - t).total_seconds() // 3600) for t in history}),
            burst=burst,
        )

    # --- correlation -------------------------------------------------------

    def related(
        self, indicators: set[tuple[str, str]], exclude_id: str | None = None, limit: int = 20
    ) -> list[RelatedCase]:
        if not indicators:
            return []
        shared: dict[str, list[SharedIndicator]] = defaultdict(list)
        with self.db.connect() as conn:
            for kind, value in indicators:
                for row in conn.execute(
                    "SELECT analysis_id FROM indicators WHERE kind = ? AND value = ?", (kind, value)
                ):
                    if row["analysis_id"] != exclude_id:
                        shared[row["analysis_id"]].append(SharedIndicator(kind=kind, value=value))
            if not shared:
                return []
            ids = sorted(shared, key=lambda i: len(shared[i]), reverse=True)[:limit]
            marks = ",".join("?" * len(ids))
            rows = conn.execute(
                f"SELECT id, subject, from_address, created_at, score, verdict FROM analyses WHERE id IN ({marks})", ids
            ).fetchall()
        by_id = {row["id"]: row for row in rows}
        return [
            RelatedCase(
                id=i,
                subject=by_id[i]["subject"],
                from_address=by_id[i]["from_address"],
                created_at=by_id[i]["created_at"],
                score=by_id[i]["score"],
                verdict=by_id[i]["verdict"],
                shared=shared[i],
            )
            for i in ids
            if i in by_id
        ]

    def graph(self, analysis_id: str | None = None, max_cases: int = 200) -> CampaignGraph:
        """Case/indicator graph. With an id: its 2-step neighbourhood; otherwise indicators shared by 2+ cases."""
        with self.db.connect() as conn:
            if analysis_id:
                case_ids = {analysis_id}
                for _ in range(2):
                    marks = ",".join("?" * len(case_ids))
                    rows = conn.execute(
                        f"SELECT DISTINCT i2.analysis_id FROM indicators i1 JOIN indicators i2"
                        f" ON i1.kind = i2.kind AND i1.value = i2.value WHERE i1.analysis_id IN ({marks})",
                        list(case_ids),
                    ).fetchall()
                    case_ids |= {r[0] for r in rows}
                    if len(case_ids) >= max_cases:
                        break
                marks = ",".join("?" * len(case_ids))
                links = conn.execute(
                    f"SELECT analysis_id, kind, value FROM indicators WHERE analysis_id IN ({marks})", list(case_ids)
                ).fetchall()
            else:
                links = conn.execute(
                    "SELECT i.analysis_id, i.kind, i.value FROM indicators i JOIN ("
                    "  SELECT kind, value FROM indicators GROUP BY kind, value HAVING COUNT(*) > 1"
                    ") s ON s.kind = i.kind AND s.value = i.value"
                    " WHERE i.analysis_id IN (SELECT id FROM analyses ORDER BY created_at DESC LIMIT ?)",
                    (max_cases,),
                ).fetchall()
            per_indicator = Counter((r["kind"], r["value"]) for r in links)
            links = [r for r in links if per_indicator[(r["kind"], r["value"])] > 1]
            case_ids = {r["analysis_id"] for r in links} | ({analysis_id} if analysis_id else set())
            marks = ",".join("?" * len(case_ids)) or "''"
            cases = conn.execute(
                f"SELECT id, subject, score FROM analyses WHERE id IN ({marks})", list(case_ids)
            ).fetchall()

        nodes = [
            GraphNode(id=f"case:{c['id']}", kind="case", label=c["subject"] or "(no subject)", score=c["score"])
            for c in cases
        ]
        known = {n.id for n in nodes}
        indicator_nodes: dict[str, GraphNode] = {}
        edges: list[GraphEdge] = []
        for row in links:
            case_node = f"case:{row['analysis_id']}"
            if case_node not in known:
                continue
            node_id = f"{row['kind']}:{row['value']}"
            indicator_nodes.setdefault(node_id, GraphNode(id=node_id, kind=row["kind"], label=row["value"]))
            edges.append(GraphEdge(source=case_node, target=node_id))
        return CampaignGraph(nodes=nodes + list(indicator_nodes.values()), edges=edges)

    # --- dashboard ---------------------------------------------------------

    def stats(self, days: int = 30) -> Stats:
        since = _iso(datetime.now(UTC) - timedelta(days=days))
        with self.db.connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
            by_level = dict(conn.execute("SELECT level, COUNT(*) FROM analyses GROUP BY level").fetchall())
            by_verdict = dict(conn.execute("SELECT verdict, COUNT(*) FROM analyses GROUP BY verdict").fetchall())
            countries = conn.execute(
                "SELECT country, COUNT(*) c FROM analyses WHERE country IS NOT NULL AND level IN ('high','critical')"
                " GROUP BY country ORDER BY c DESC LIMIT 8"
            ).fetchall()
            asns = conn.execute(
                "SELECT asn, COUNT(*) c FROM analyses WHERE asn IS NOT NULL AND level IN ('high','critical')"
                " GROUP BY asn ORDER BY c DESC LIMIT 8"
            ).fetchall()
            daily = conn.execute(
                "SELECT substr(created_at, 1, 10) d, COUNT(*),"
                " SUM(CASE WHEN level IN ('high','critical') THEN 1 ELSE 0 END),"
                " SUM(CASE WHEN level = 'medium' THEN 1 ELSE 0 END)"
                " FROM analyses WHERE created_at >= ? GROUP BY d ORDER BY d",
                (since,),
            ).fetchall()
        return Stats(
            total=total,
            by_level=by_level,
            by_verdict=by_verdict,
            top_countries=[(r[0], r[1]) for r in countries],
            top_origin_asns=[(r[0], r[1]) for r in asns],
            daily=[(r[0], r[1], r[2], r[3]) for r in daily],
        )
