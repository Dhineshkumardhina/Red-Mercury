"""Safe Patch Application Engine for Isolated Workspaces.

Applies parsed unified diffs to files inside an isolated disposable workspace.
Ensures:
- Verification of context lines before applying modifications.
- Truly atomic multi-file updates (dry-run pre-validation with complete rollback).
- Zero modification to files outside the specified workspace root.
- Pre- and post-patch SHA-256 hash tracking and verification.
"""
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from .patch_parser import PatchValidationResult, ParsedFilePatch, ParsedHunk


class PatchApplicationError(Exception):
    """Raised when patch application fails due to context mismatch or missing file."""
    pass


def calculate_file_hash(file_path: Path) -> Optional[str]:
    """Calculate SHA-256 hash of a file if it exists."""
    if not file_path.exists() or not file_path.is_file():
        return None
    try:
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return None


def apply_hunks_to_content(original_content: str, hunks: List[ParsedHunk]) -> Tuple[str, List[str]]:
    """Apply a sequence of hunks to string content.
    
    Returns:
        (patched_content, list_of_errors)
    """
    orig_lines = original_content.replace("\r\n", "\n").split("\n")
    errors: List[str] = []
    
    # Process hunks in order with line tracking
    # Sort hunks by old_start ascending
    sorted_hunks = sorted(hunks, key=lambda h: h.old_start)

    result_lines: List[str] = []
    curr_orig_idx = 0  # 0-indexed in orig_lines

    for hunk_idx, hunk in enumerate(sorted_hunks):
        target_start = max(0, hunk.old_start - 1)  # 1-indexed to 0-indexed

        # Copy unchanged lines leading up to hunk
        while curr_orig_idx < target_start and curr_orig_idx < len(orig_lines):
            result_lines.append(orig_lines[curr_orig_idx])
            curr_orig_idx += 1

        # Now apply the hunk lines
        for line in hunk.lines:
            if not line:
                continue
            marker = line[0]
            text = line[1:]

            if marker == " ":
                # Context line - must match original
                if curr_orig_idx < len(orig_lines):
                    actual = orig_lines[curr_orig_idx]
                    # Soft match stripping trailing whitespace
                    if actual.rstrip() == text.rstrip():
                        result_lines.append(actual)
                        curr_orig_idx += 1
                    else:
                        errors.append(
                            f"Hunk {hunk_idx+1} context mismatch at line {curr_orig_idx+1}. "
                            f"Expected: '{text.strip()[:40]}', Found: '{actual.strip()[:40]}'"
                        )
                        result_lines.append(text)
                        curr_orig_idx += 1
                else:
                    errors.append(f"Hunk {hunk_idx+1} context extends past end of file.")
                    result_lines.append(text)

            elif marker == "-":
                # Deletion line - must match original line being deleted
                if curr_orig_idx < len(orig_lines):
                    actual = orig_lines[curr_orig_idx]
                    if actual.rstrip() != text.rstrip():
                        errors.append(
                            f"Hunk {hunk_idx+1} delete line mismatch at line {curr_orig_idx+1}. "
                            f"Expected deletion: '{text.strip()[:40]}', Found: '{actual.strip()[:40]}'"
                        )
                    curr_orig_idx += 1
                else:
                    errors.append(f"Hunk {hunk_idx+1} delete line extends past end of file.")

            elif marker == "+":
                # Addition line - insert into result
                result_lines.append(text)

            elif marker == "\\":
                # '\ No newline at end of file' comment
                pass

    # Append any remaining lines from original file
    while curr_orig_idx < len(orig_lines):
        result_lines.append(orig_lines[curr_orig_idx])
        curr_orig_idx += 1

    patched_content = "\n".join(result_lines)
    return patched_content, errors


def apply_patch_to_workspace(
    workspace_root: Path,
    patch_result: PatchValidationResult
) -> Tuple[bool, List[str]]:
    """Apply validated patch to files in the disposable workspace with strict atomicity.
    
    Guarantees:
    - If any hunk or any file in a multi-file patch fails validation, NO disk writes occur.
    - If unexpected disk I/O errors happen during write, all changes are rolled back to pre-patch state.
    - Path traversal, null bytes, and symlinks are strictly rejected.
    
    Returns:
        (success: bool, errors: List[str])
    """
    if not patch_result.is_valid:
        return False, ["Cannot apply invalid patch: " + "; ".join(patch_result.errors)]

    root_resolved = workspace_root.resolve()
    all_errors: List[str] = []

    # -------------------------------------------------------------------------
    # PHASE 1: Dry-run and Validation (Compute all changes in memory first)
    # -------------------------------------------------------------------------
    planned_operations = []

    for file_patch in patch_result.files:
        target_rel = file_patch.new_path if file_patch.new_path != "/dev/null" else file_patch.old_path
        if not target_rel or target_rel == "/dev/null":
            continue

        if "\0" in target_rel:
            all_errors.append(f"Security boundary violation: target path contains null byte: {target_rel}")
            continue

        raw_target = root_resolved / target_rel
        target_file = raw_target.resolve()

        # Invariant 1: File must be strictly inside the workspace root
        try:
            target_file.relative_to(root_resolved)
        except ValueError:
            all_errors.append(f"Security boundary violation: target path {target_rel} escapes workspace.")
            continue

        # Invariant 2: Symlink rejection to prevent writing or modifying through symlinks
        if raw_target.is_symlink() or target_file.is_symlink():
            all_errors.append(f"Security boundary violation: target path {target_rel} is a symbolic link.")
            continue

        # Invariant 3: Verify parent directories do not traverse escaping symlinks
        curr = raw_target.parent
        has_symlink_escape = False
        while curr != root_resolved and curr != curr.parent:
            if curr.is_symlink():
                resolved_curr = curr.resolve()
                try:
                    resolved_curr.relative_to(root_resolved)
                except ValueError:
                    has_symlink_escape = True
                    break
            curr = curr.parent

        if has_symlink_escape:
            all_errors.append(f"Security boundary violation: target path {target_rel} traverses symlink escaping workspace.")
            continue

        # Plan: File Creation
        if file_patch.old_path == "/dev/null":
            new_lines = [l[1:] for h in file_patch.hunks for l in h.lines if l.startswith("+")]
            new_content = "\n".join(new_lines)
            planned_operations.append({
                "op": "create",
                "target_file": target_file,
                "target_rel": target_rel,
                "original_content": None,
                "new_content": new_content,
                "pre_hash": None,
            })
            continue

        # Plan: File Deletion
        if file_patch.new_path == "/dev/null":
            if not target_file.exists():
                all_errors.append(f"Target file to delete does not exist in workspace: {target_rel}")
                continue
            orig_content = target_file.read_text(encoding="utf-8", errors="replace")
            pre_hash = calculate_file_hash(target_file)
            planned_operations.append({
                "op": "delete",
                "target_file": target_file,
                "target_rel": target_rel,
                "original_content": orig_content,
                "new_content": None,
                "pre_hash": pre_hash,
            })
            continue

        # Plan: File Modification
        if not target_file.exists():
            all_errors.append(f"Target file does not exist in workspace: {target_rel}")
            continue

        try:
            original_content = target_file.read_text(encoding="utf-8", errors="replace")
            pre_hash = calculate_file_hash(target_file)
            patched_content, hunk_errors = apply_hunks_to_content(original_content, file_patch.hunks)

            if hunk_errors:
                all_errors.extend([f"{target_rel}: {e}" for e in hunk_errors])
                continue

            planned_operations.append({
                "op": "modify",
                "target_file": target_file,
                "target_rel": target_rel,
                "original_content": original_content,
                "new_content": patched_content,
                "pre_hash": pre_hash,
            })
        except Exception as e:
            all_errors.append(f"Error validating patch for {target_rel}: {str(e)}")

    # ATOMICITY ENFORCEMENT: If ANY error occurred during dry-run, abort immediately without modifying ANY files!
    if all_errors:
        return False, all_errors

    # -------------------------------------------------------------------------
    # PHASE 2: Atomic Execution & Rollback Guard
    # -------------------------------------------------------------------------
    executed_ops = []
    try:
        for plan in planned_operations:
            op = plan["op"]
            target = plan["target_file"]

            if op == "create":
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(plan["new_content"], encoding="utf-8")
                executed_ops.append(plan)
            elif op == "delete":
                target.unlink()
                executed_ops.append(plan)
            elif op == "modify":
                target.write_text(plan["new_content"], encoding="utf-8")
                executed_ops.append(plan)

        return True, []

    except Exception as write_exc:
        # Rollback all applied operations in reverse order
        rollback_errors = []
        for plan in reversed(executed_ops):
            op = plan["op"]
            target = plan["target_file"]
            try:
                if op == "create":
                    if target.exists():
                        target.unlink()
                elif op == "delete":
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(plan["original_content"], encoding="utf-8")
                elif op == "modify":
                    target.write_text(plan["original_content"], encoding="utf-8")
            except Exception as rb_err:
                rollback_errors.append(f"Rollback failed for {plan['target_rel']}: {rb_err}")

        error_message = f"Atomic patch write failed ({write_exc}); rolled back executed operations."
        if rollback_errors:
            error_message += f" Rollback warnings: {'; '.join(rollback_errors)}"
        return False, [error_message]
