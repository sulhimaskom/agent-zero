import json
import os
import subprocess

from python.helpers.constants import Network
from python.helpers.tool import Response, Tool


class State:
    @staticmethod
    async def create(agent):
        state = State(agent)
        return state

    def __init__(self, agent):
        self.agent = agent
        self.audit_results = {}
        self.opportunities = []


class LighthouseAuditor(Tool):
    """
    Run Lighthouse audit on a URL to find optimization opportunities.
    Checks performance, accessibility, best practices, and SEO.
    """

    async def execute(
        self,
        url: str | None = None,
        categories: str = "performance,accessibility,best-practices,seo",
        device: str = "desktop",
        **kwargs,
    ) -> Response:
        """
        Run Lighthouse audit and report optimization opportunities.

        Args:
            url: The URL to audit (default: http://localhost:50001)
            categories: Comma-separated list of categories to audit (default: all)
            device: Device type - 'desktop' or 'mobile' (default: desktop)
        """
        if url is None:
            url = f"http://{Network.DEFAULT_HOSTNAME}:{Network.BROCULA_PORT_DEFAULT}"
        await self.agent.handle_intervention()

        state = await self.agent.get_tool_state(self, State)
        state.opportunities = []

        try:
            # Check if lighthouse is installed
            try:
                result = subprocess.run(
                    ["lighthouse", "--version"], capture_output=True, text=True, timeout=10
                )
                if result.returncode != 0:
                    raise Exception("Lighthouse not available")
            except Exception:
                return Response(
                    message="❌ Lighthouse not installed. Install: npm install -g lighthouse",
                    break_loop=False,
                    additional={"error": "lighthouse_not_installed", "has_issues": True},
                )

            # Prepare output file
            output_file = "/tmp/lighthouse-report.json"

            # Build lighthouse command
            categories_list = [c.strip() for c in categories.split(",")]
            category_flags = []
            for cat in categories_list:
                category_flags.extend(["--only-categories", cat])

            cmd = [
                "lighthouse",
                url,
                "--output=json",
                f"--output-path={output_file}",
                "--chrome-flags=--headless --no-sandbox --disable-gpu",
                f"--preset={device}",
                "--quiet",
                *category_flags,
            ]

            self.set_progress(f"Running Lighthouse audit on {url} ({device})...")

            # Run lighthouse
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.returncode != 0 and not os.path.exists(output_file):
                return Response(
                    message=f"❌ Lighthouse audit failed: {result.stderr}",
                    break_loop=False,
                    additional={"error": result.stderr, "has_issues": True},
                )

            # Parse results
            if not os.path.exists(output_file):
                return Response(
                    message="❌ Lighthouse report file not created",
                    break_loop=False,
                    additional={"error": "no_report", "has_issues": True},
                )

            with open(output_file) as f:
                report = json.load(f)

            # Extract scores
            scores = {}
            for category in report.get("categories", {}).values():
                cat_id = category.get("id", "unknown")
                score = category.get("score", 0)
                scores[cat_id] = round(score * 100) if score is not None else 0

            # Extract opportunities (performance diagnostics)
            opportunities = []
            audits = report.get("audits", {})

            for audit_id, audit in audits.items():
                if audit.get("details", {}).get("type") == "opportunity":
                    score = audit.get("score", 1)
                    if score is not None and score < 1:
                        opportunities.append(
                            {
                                "id": audit_id,
                                "title": audit.get("title", audit_id),
                                "description": audit.get("description", ""),
                                "score": score,
                                "display_value": audit.get("displayValue", ""),
                                "numeric_value": audit.get("numericValue", 0),
                                "details": audit.get("details", {}),
                            }
                        )

            # Sort by impact (lower score = higher priority)
            opportunities.sort(key=lambda x: x["score"])
            state.opportunities = opportunities

            # Generate report
            report_lines = [f"Lighthouse Audit Results for {url}", "=" * 60, ""]

            # Report scores
            report_lines.append("📊 Scores:")
            for cat, score in scores.items():
                emoji = "🟢" if score >= 90 else "🟡" if score >= 50 else "🔴"
                report_lines.append(f"  {emoji} {cat.capitalize()}: {score}/100")
            report_lines.append("")

            # Report opportunities
            if opportunities:
                report_lines.append(f"🔧 Optimization Opportunities ({len(opportunities)} found):")
                for i, opp in enumerate(opportunities[:15], 1):  # Limit to 15
                    priority = (
                        "🔴 HIGH"
                        if opp["score"] < 0.5
                        else "🟡 MEDIUM"
                        if opp["score"] < 0.9
                        else "🟢 LOW"
                    )
                    report_lines.append(f"\n  {i}. [{priority}] {opp['title']}")
                    report_lines.append(f"     Impact: {opp.get('display_value', 'N/A')}")
                    if opp["description"]:
                        # Clean up description (remove markdown links)
                        desc = opp["description"].replace("[Learn more]", "").replace("(...)", "")
                        report_lines.append(f"     Details: {desc[:150]}")

                if len(opportunities) > 15:
                    report_lines.append(f"\n  ... and {len(opportunities) - 15} more opportunities")
            else:
                report_lines.append("✅ No significant optimization opportunities found!")

            # Summary
            low_scores = [cat for cat, score in scores.items() if score < 90]
            report_lines.append("")
            report_lines.append("=" * 60)
            if low_scores:
                report_lines.append(f"⚠️ Categories needing improvement: {', '.join(low_scores)}")
            else:
                report_lines.append("✅ All categories score 90+ (excellent!)")

            message = "\n".join(report_lines)

            additional = {
                "url": url,
                "scores": scores,
                "opportunities_count": len(opportunities),
                "opportunities": opportunities[:20],
                "low_score_categories": low_scores,
                "has_issues": len(opportunities) > 0 or len(low_scores) > 0,
                "report_file": output_file,
            }

            return Response(message=message, break_loop=False, additional=additional)

        except subprocess.TimeoutExpired:
            return Response(
                message="❌ Lighthouse audit timed out (120s)",
                break_loop=False,
                additional={"error": "timeout", "has_issues": True},
            )
        except Exception as e:
            return Response(
                message=f"❌ Lighthouse audit failed: {e!s}",
                break_loop=False,
                additional={"error": str(e), "has_issues": True},
            )
