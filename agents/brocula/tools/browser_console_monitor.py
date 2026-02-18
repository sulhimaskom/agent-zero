import asyncio

from python.helpers.tool import Response, Tool


class BrowserConsoleMonitor(Tool):
    """
    Monitor browser console for errors and warnings using Playwright.
    Captures JavaScript errors, warnings, and other console output.
    """

    async def execute(
        self,
        url: str = "http://localhost:50001",
        wait_time: int = 3,
        capture_level: str = "all",
        **kwargs,
    ) -> Response:
        """
        Monitor browser console for errors and warnings.

        Args:
            url: The URL to monitor (default: http://localhost:50001)
            wait_time: Seconds to wait for scripts to execute (default: 3)
            capture_level: What to capture - 'errors', 'warnings', or 'all' (default: all)
        """
        await self.agent.handle_intervention()

        try:
            # Import playwright here to avoid dependency issues if not installed
            try:
                from playwright.async_api import async_playwright
            except ImportError:
                return Response(
                    message="❌ Playwright not installed. Run: pip install playwright && python -m playwright install chromium",
                    break_loop=False,
                    additional={"error": "playwright_not_installed", "has_issues": True},
                )

            self.set_progress(f"Opening browser to monitor console at {url}...")

            logs = []
            failed_requests = []

            def handle_console(msg):
                logs.append(
                    {
                        "type": msg.type,
                        "text": msg.text,
                        "location": str(msg.location) if hasattr(msg, "location") else None,
                    }
                )

            def handle_response(response):
                if response.status >= 400:
                    failed_requests.append(
                        {
                            "url": response.url,
                            "status": response.status,
                            "status_text": response.status_text,
                        }
                    )

            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                page.on("console", handle_console)
                page.on("response", handle_response)

                try:
                    await page.goto(url, wait_until="networkidle", timeout=30000)
                    await asyncio.sleep(wait_time)
                except Exception as e:
                    await browser.close()
                    return Response(
                        message=f"❌ Failed to load page: {e!s}",
                        break_loop=False,
                        additional={"error": str(e), "has_issues": True},
                    )

                await browser.close()

            # Analyze results
            errors = [log for log in logs if log["type"] == "error"]
            warnings = [log for log in logs if log["type"] == "warning"]
            info_logs = [log for log in logs if log["type"] not in ["error", "warning"]]

            # Generate report
            report_lines = [f"Browser Console Report for {url}", "=" * 60, ""]

            # Summary
            report_lines.append("📊 Summary:")
            report_lines.append(f"  Total logs: {len(logs)}")
            report_lines.append(f"  Errors: {len(errors)}")
            report_lines.append(f"  Warnings: {len(warnings)}")
            report_lines.append(f"  Failed requests: {len(failed_requests)}")
            report_lines.append("")

            # Errors section
            if errors:
                report_lines.append(f"🔴 ERRORS ({len(errors)}):")
                for i, log in enumerate(errors[:10], 1):  # Limit to 10
                    text = log["text"][:150] + "..." if len(log["text"]) > 150 else log["text"]
                    report_lines.append(f"  {i}. {text}")
                if len(errors) > 10:
                    report_lines.append(f"  ... and {len(errors) - 10} more errors")
                report_lines.append("")
            else:
                report_lines.append("✅ No console errors found!")
                report_lines.append("")

            # Warnings section
            if warnings:
                report_lines.append(f"🟡 WARNINGS ({len(warnings)}):")
                for i, log in enumerate(warnings[:5], 1):  # Limit to 5
                    text = log["text"][:150] + "..." if len(log["text"]) > 150 else log["text"]
                    report_lines.append(f"  {i}. {text}")
                if len(warnings) > 5:
                    report_lines.append(f"  ... and {len(warnings) - 5} more warnings")
                report_lines.append("")

            # Failed requests section
            if failed_requests:
                report_lines.append(f"🔴 FAILED REQUESTS ({len(failed_requests)}):")
                for req in failed_requests[:5]:
                    url_short = req["url"][:80] + "..." if len(req["url"]) > 80 else req["url"]
                    report_lines.append(f"  - {req['status']} {req['status_text']}")
                    report_lines.append(f"    {url_short}")
                report_lines.append("")

            # All logs if requested
            if capture_level == "all" and logs:
                report_lines.append("📋 ALL LOGS:")
                for log in logs[:20]:  # Limit output
                    icon = (
                        "🔴"
                        if log["type"] == "error"
                        else "🟡" if log["type"] == "warning" else "ℹ️"
                    )
                    text = log["text"][:100] + "..." if len(log["text"]) > 100 else log["text"]
                    report_lines.append(f"  {icon} [{log['type']}] {text}")
                if len(logs) > 20:
                    report_lines.append(f"  ... and {len(logs) - 20} more logs")

            # Final status
            report_lines.append("")
            report_lines.append("=" * 60)
            if errors:
                report_lines.append(
                    f"⚠️  Status: {len(errors)} console error(s) found - NEEDS ATTENTION"
                )
                has_issues = True
            elif warnings:
                report_lines.append(
                    f"⚠️  Status: {len(warnings)} warning(s) found - Review recommended"
                )
                has_issues = True
            else:
                report_lines.append("✅ Status: Console is clean!")
                has_issues = False

            message = "\n".join(report_lines)

            additional = {
                "url": url,
                "total_logs": len(logs),
                "errors_count": len(errors),
                "warnings_count": len(warnings),
                "failed_requests_count": len(failed_requests),
                "errors": errors[:20],
                "warnings": warnings[:10],
                "failed_requests": failed_requests[:10],
                "has_issues": has_issues,
            }

            return Response(message=message, break_loop=False, additional=additional)

        except Exception as e:
            return Response(
                message=f"❌ Browser console monitoring failed: {e!s}",
                break_loop=False,
                additional={"error": str(e), "has_issues": True},
            )
