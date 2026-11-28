"""The deploys to production run one at a time (#871).

Run by the job post-deploy-scripts of .github/workflows/cicd.yml, with the
standard library only: the workflow is read as text.
"""

import re
import unittest
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parent.parent / "workflows" / "cicd.yml"


def top_level_block(text: str, key: str) -> list[str]:
    """The lines of the top-level KEY of the workflow, without comments."""
    lines, inside = [], False
    for line in text.splitlines():
        if re.match(rf"^{key}:\s*$", line):
            inside = True
            continue
        if inside:
            if line and not line.startswith((" ", "#")):
                break
            if line.strip() and not line.strip().startswith("#"):
                lines.append(line.strip())
    return lines


class DeployConcurrency(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text(encoding="utf-8")
        self.block = top_level_block(self.text, "concurrency")

    def test_one_deploy_at_a_time_never_cancelled(self):
        # Two pushes on master 4 s apart (28/11/2026): two deploys at once,
        # one failed with "No such container".
        self.assertIn("cancel-in-progress: false", self.block)
        group = next(line for line in self.block if line.startswith("group:"))
        self.assertIn("'production-deploy'", group)

    def test_a_pull_request_never_waits_for_a_deploy(self):
        group = next(line for line in self.block if line.startswith("group:"))
        self.assertIn("github.event_name == 'pull_request'", group)
        self.assertIn("github.run_id", group)

    def test_every_event_that_deploys_shares_the_group(self):
        # push on master, workflow_dispatch and repository_dispatch deploy:
        # none of them is the pull_request of the unique group.
        on = top_level_block(self.text, "on")
        events = {line.split(":", 1)[0] for line in on if not line.startswith(("branches", "types"))}
        self.assertEqual(events, {"push", "pull_request", "workflow_dispatch", "repository_dispatch"})


if __name__ == "__main__":
    unittest.main()
