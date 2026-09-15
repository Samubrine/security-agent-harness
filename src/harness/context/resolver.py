"""Context resolution: turn a CLI invocation into a frozen, authorised starting point.

This is the step that mints authority. The signed scope record is verified before anything else
happens, and it is the only source of the aliases the model will ever be shown.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from harness.context.retrieval import retrieve_for_plan
from harness.memory.manager import MemoryManager
from harness.models import Grant, MemoryDigests, RetrievedMemory, ScopeFile, SkillSpec
from harness.policy.grants import GrantBook, mint_from_scope
from harness.policy.scope import load_scope
from harness.skills import load_skill


@dataclass
class ResolvedContext:
    run_id: str
    objective: str
    skill: SkillSpec
    scope: ScopeFile
    grants: GrantBook
    memory: MemoryDigests
    baseline_text: str
    active_text: str
    retrieved: list[RetrievedMemory]

    def grant_map(self) -> dict[str, Grant]:
        return {grant.id: grant for grant in self.grants.grants}

    def aliases(self) -> list[str]:
        return sorted({grant.alias for grant in self.grants.grants})


class ContextResolver:
    def __init__(self, *, root: Path, memory: MemoryManager, index: object) -> None:
        self.root = Path(root)
        self.memory = memory
        self.index = index

    def resolve(
        self,
        *,
        objective: str,
        skill_name: str,
        scope_path: Path,
        public_key_path: Path | None,
        run_id: str,
        retrieved_limit: int = 3,
    ) -> ResolvedContext:
        # A run cannot exist without a verifiable authorisation record; every failure below is
        # fatal before the model is ever consulted.
        scope = load_scope(scope_path, public_key_path=public_key_path)
        skill = load_skill(skill_name)
        grants = mint_from_scope(scope, run_id=run_id)

        baseline_text = self.memory.load_baseline()
        active_text = self.memory.load_active()
        retrieved = retrieve_for_plan(
            self.index, objective=objective, skill=skill, limit=retrieved_limit
        )
        digests = self.memory.digests()

        return ResolvedContext(
            run_id=run_id,
            objective=objective,
            skill=skill,
            scope=scope,
            grants=grants,
            memory=digests,
            baseline_text=baseline_text,
            active_text=active_text,
            retrieved=retrieved,
        )
