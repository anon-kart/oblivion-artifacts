from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil


@dataclass
class FoundrySwapWorkspace:
    """
    Isolated validation workspace.

    Instead of swapping candidate Solidity into the canonical Foundry project,
    this class creates a scratch copy of the entire Foundry project under out_dir
    and performs all mutations there.

    Result:
      - canonical input files are never modified
      - candidate compilation/tests run against the scratch project only
      - no overwrite/edit-log noise on the original source tree
    """

    foundry_root: Path
    target_relpath: str
    original_src: Path
    candidate_src: Path
    out_dir: Path

    def __post_init__(self) -> None:
        self.foundry_root = Path(self.foundry_root).resolve()
        self.original_src = Path(self.original_src).resolve()
        self.candidate_src = Path(self.candidate_src).resolve()
        self.out_dir = Path(self.out_dir).resolve()

        self.workspace_root = self.out_dir / "_foundry_workspace"
        self.target_path = self.workspace_root / self.target_relpath
        self.backup_path = self.out_dir / (Path(self.target_relpath).name + ".bak")

    def _same_file(self, a: Path, b: Path) -> bool:
        """
        Best-effort same-file check that tolerates non-existing paths.
        """
        try:
            return a.resolve() == b.resolve()
        except Exception:
            return str(a) == str(b)

    def prepare(self) -> None:
        """
        Create a fresh scratch copy of the Foundry project for this validation run.
        """
        if self.workspace_root.exists():
            shutil.rmtree(self.workspace_root)

        shutil.copytree(self.foundry_root, self.workspace_root)
        self.target_path.parent.mkdir(parents=True, exist_ok=True)

    def put_original(self) -> None:
        """
        Put the ORIGINAL source into the scratch workspace target path.
        Never touches the canonical Foundry project.
        """
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self.target_path.parent.mkdir(parents=True, exist_ok=True)

        if self._same_file(self.original_src, self.target_path):
            return

        shutil.copy2(self.original_src, self.target_path)

    def swap_in(self) -> None:
        """
        Copy the candidate into the scratch workspace target path.
        Back up the current scratch target first.
        Never touches the canonical Foundry project.
        """
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self.target_path.parent.mkdir(parents=True, exist_ok=True)

        # Backup current scratch target if it exists
        if self.target_path.exists():
            if not self._same_file(self.target_path, self.backup_path):
                shutil.copy2(self.target_path, self.backup_path)
        else:
            if self.original_src.exists() and not self._same_file(self.original_src, self.backup_path):
                shutil.copy2(self.original_src, self.backup_path)

        # Copy candidate into scratch target
        if not self._same_file(self.candidate_src, self.target_path):
            shutil.copy2(self.candidate_src, self.target_path)

    def restore(self) -> None:
        """
        Restore the scratch target from backup.
        This does NOT touch the canonical Foundry project.
        """
        if not self.backup_path.exists():
            raise RuntimeError(f"Missing backup: {self.backup_path}")

        self.target_path.parent.mkdir(parents=True, exist_ok=True)

        if self._same_file(self.backup_path, self.target_path):
            return

        shutil.copy2(self.backup_path, self.target_path)

    @property
    def active_foundry_root(self) -> Path:
        """
        The Foundry root that validator/test/coverage should use.
        """
        return self.workspace_root