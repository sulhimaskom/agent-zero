import asyncio

from playwright.async_api import async_playwright

from python.helpers.constants import Network
from python.helpers.playwright import ensure_playwright_binary
from python.helpers.tool import Response, Tool


class State:
    @staticmethod
    async def create(agent):
        state = State(agent)
        return state

    def __init__(self, agent):
        self.agent = agent
        self.console_logs = []
        self.errors_found = []
        self.warnings_found = []


class browser_console_checker(Tool):
    """
    Check browser console for errors and warnings using Playwright.
    Navigates to a URL, captures console output, and reports any errors or warnings.
    """

    async def execute(self, url: str = None, wait_time: int = 5, **kwargs) -> Response:
        """
        Check browser console for errors and warnings.

        Args:
            url: The URL to navigate to (default: http://localhost:50001)
            wait_time: Time to wait after page load for console messages (default: 5 seconds)
        """
        if url is None:
            url = f"http://{Network.DEFAULT_HOSTNAME}:{Network.BROCULA_PORT_DEFAULT}"
        await self.agent.handle_intervention()

        state = await self.agent.get_tool_state(self, State)
        state.console_logs = []
        state.errors_found = []
        state.warnings_found = []

        try:
            # Ensure playwright binary is available
            ensure_playwright_binary()

            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context()
                page = await context.new_page()

                # Listen to console messages
                def handle_console(msg):
                    log_entry = {
                        "type": msg.type,
                        "text": msg.text,
                        "location": msg.location if hasattr(msg, "location") else None,
                    }
                    state.console_logs.append(log_entry)

                    if msg.type == "error":
                        state.errors_found.append(log_entry)
                    elif msg.type == "warning":
                        state.warnings_found.append(log_entry)

                page.on("console", handle_console)

                # Navigate to the URL
                self.set_progress(f"Navigating to {url}...")
                await page.goto(url, wait_until="networkidle")

                # Wait for additional console messages
                self.set_progress(f"Waiting {wait_time}s for console messages...")
                await asyncio.sleep(wait_time)

                # Close browser
                await browser.close()

            # Prepare report
            report_lines = [
                f"Browser Console Check Results for {url}",
                "=" * 60,
                f"Total console messages: {len(state.console_logs)}",
                f"Errors: {len(state.errors_found)}",
                f"Warnings: {len(state.warnings_found)}",
                "",
            ]

            if state.errors_found:
                report_lines.append("❌ ERRORS FOUND (MUST FIX IMMEDIATELY):")
                for i, error in enumerate(state.errors_found[:20], 1):  # Limit to 20
                    report_lines.append(f"  {i}. [{error['type'].upper()}] {error['text'][:200]}")
                if len(state.errors_found) > 20:
                    report_lines.append(f"  ... and {len(state.errors_found) - 20} more errors")
                report_lines.append("")

            if state.warnings_found:
                report_lines.append("⚠️ WARNINGS FOUND:")
                for i, warning in enumerate(state.warnings_found[:20], 1):  # Limit to 20
                    report_lines.append(
                        f"  {i}. [{warning['type'].upper()}] {warning['text'][:200]}"
                    )
                if len(state.warnings_found) > 20:
                    report_lines.append(f"  ... and {len(state.warnings_found) - 20} more warnings")
                report_lines.append("")

            if not state.errors_found and not state.warnings_found:
                report_lines.append("✅ No console errors or warnings found!")

            message = "\n".join(report_lines)

            # Return additional data for further processing
            additional = {
                "url": url,
                "total_logs": len(state.console_logs),
                "error_count": len(state.errors_found),
                "warning_count": len(state.warnings_found),
                "errors": state.errors_found,
                "warnings": state.warnings_found,
                "has_errors": len(state.errors_found) > 0,
                "has_warnings": len(state.warnings_found) > 0,
            }

            return Response(message=message, break_loop=False, additional=additional)

        except Exception as e:
            return Response(
                message=f"❌ Failed to check browser console: {e!s}",
                break_loop=False,
                additional={"error": str(e), "has_errors": True},
            )
