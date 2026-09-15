"""Declarative skills.

A skill is data, not code: adding one must not require a runtime change (design 01 section 11).
It declares which logical capabilities may enter the action catalogue and how much verification
the resulting findings need.
"""

from __future__ import annotations

from harness.skills.loader import default_skills_dir, list_skills, load_skill

__all__ = ["default_skills_dir", "list_skills", "load_skill"]
