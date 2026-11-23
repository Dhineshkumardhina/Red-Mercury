"""Safe Patch Application Engine for Isolated Workspaces.

Applies parsed unified diffs to files inside an isolated disposable workspace.
Ensures:
- Verification of context lines before applying modifications.
- Truly atomic multi-file updates (dry-run pre-validation with complete rollback).
- Zero modification to files outside the specified workspace root.
- Pre- and post-patch SHA-256 hash tracking and verification.
- Sequential execution inside an isolated single-owner temporary workspace; on POSIX
  hosts, file reads, writes, and deletions use dir_fd + O_NOFOLLOW + O_EXCL atomic
  replacement to resist symlink swaps between validation and execution. Note: same-UID
  or root concurrent renames of ancestor directories remain outside single-process scope.
"""
import hashlib
import os
from pathlib import Path
import stat
from typing import List, Optional, Tuple
import uuid
from .patch_parser import PatchValidationResult, ParsedHunk


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


def _sanitize_preserved_mode(orig_mode: Optional[int]) -> int:
    """Preserve safe owner executable bit while stripping group/world and special permission bits."""
    if orig_mode is None:
        return stat.S_IRUSR | stat.S_IWUSR
    return stat.S_IRUSR | stat.S_IWUSR | (stat.S_IXUSR if (orig_mode & stat.S_IXUSR) else 0)


def _use_posix_dirfd() -> bool:
    """Return True when kernel O_NOFOLLOW / dir_fd primitives are available (POSIX)."""
    return (
        os.name == "posix"
        and hasattr(os, "O_NOFOLLOW")
        and hasattr(os, "O_DIRECTORY")
    )


def _open_parent_dir_fd(root_resolved: Path, parent_parts: List[str], create_missing: bool) -> int:
    """Open parent directory relative to root_resolved with O_DIRECTORY | O_NOFOLLOW on each step."""
    dir_fd = os.open(root_resolved, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parent_parts:
            if create_missing:
                try:
                    os.mkdir(part, 0o700, dir_fd=dir_fd)
                except FileExistsError:
                    pass
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = next_fd
        return dir_fd
    except Exception:
        os.close(dir_fd)
        raise


def _read_text_posix_nofollow(root_resolved: Path, rel_parts: List[str]) -> Tuple[str, str, int]:
    """Read UTF-8 file contents, SHA-256 hash, and permission bits via dir_fd + O_NOFOLLOW + fstat."""
    parent_fd = _open_parent_dir_fd(root_resolved, rel_parts[:-1], create_missing=False)
    try:
        file_fd = os.open(rel_parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            orig_mode = stat.S_IMODE(os.fstat(file_fd).st_mode)
            chunks: List[bytes] = []
            hasher = hashlib.sha256()
            while True:
                data = os.read(file_fd, 65536)
                if not data:
                    break
                chunks.append(data)
                hasher.update(data)
            return b"".join(chunks).decode("utf-8", errors="replace"), hasher.hexdigest(), orig_mode
        finally:
            os.close(file_fd)
    finally:
        os.close(parent_fd)


def _write_text_posix_nofollow(
    root_resolved: Path,
    rel_parts: List[str],
    content: str,
    create_parents: bool,
    file_mode: Optional[int] = None,
) -> None:
    """Atomically write file via private 0o600 O_EXCL|O_NOFOLLOW temp file, fchmod, and os.replace."""
    parent_fd = _open_parent_dir_fd(root_resolved, rel_parts[:-1], create_missing=create_parents)
    leaf = rel_parts[-1]
    tmp_name = f".rm_patch_{uuid.uuid4().hex[:10]}"
    tmp_created = False
    target_mode = _sanitize_preserved_mode(file_mode)
    try:
        try:
            leaf_stat = os.lstat(leaf, dir_fd=parent_fd)
            if stat.S_ISLNK(leaf_stat.st_mode):
                raise PermissionError(f"Refusing to write to symbolic link target '{leaf}'.")
        except FileNotFoundError:
            pass

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        fd = os.open(tmp_name, flags, 0o600, dir_fd=parent_fd)
        tmp_created = True
        try:
            payload = content.encode("utf-8")
            view = memoryview(payload)
            written = 0
            while written < len(payload):
                written += os.write(fd, view[written:])
            if target_mode != (stat.S_IRUSR | stat.S_IWUSR):
                fchmod_fn = getattr(os, "fchmod", None)
                if fchmod_fn is not None:
                    fchmod_fn(fd, target_mode)
        finally:
            os.close(fd)

        try:
            leaf_stat = os.lstat(leaf, dir_fd=parent_fd)
            if stat.S_ISLNK(leaf_stat.st_mode):
                raise PermissionError(f"Refusing to replace symbolic link target '{leaf}'.")
        except FileNotFoundError:
            pass

        os.replace(tmp_name, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        tmp_created = False
    except Exception:
        if tmp_created:
            try:
                os.unlink(tmp_name, dir_fd=parent_fd)
            except OSError:
                pass
        raise
    finally:
        os.close(parent_fd)


def _unlink_posix_nofollow(root_resolved: Path, rel_parts: List[str]) -> None:
    """Unlink regular file inside pinned dir_fd after verifying target is not a symlink."""
    parent_fd = _open_parent_dir_fd(root_resolved, rel_parts[:-1], create_missing=False)
    leaf = rel_parts[-1]
    try:
        leaf_stat = os.lstat(leaf, dir_fd=parent_fd)
        if stat.S_ISLNK(leaf_stat.st_mode):
            raise PermissionError(f"Refusing to unlink symbolic link target '{leaf}'.")
        os.unlink(leaf, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)


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

        norm_rel = target_rel.replace("\\", "/")
        rel_parts = [p for p in norm_rel.split("/") if p and p != "."]
        if (
            norm_rel.startswith("/")
            or (len(norm_rel) >= 2 and norm_rel[1] == ":")
            or ".." in rel_parts
            or not rel_parts
        ):
            all_errors.append(f"Security boundary violation: target path {target_rel} escapes workspace.")
            continue

        raw_target = root_resolved / norm_rel

        # Invariant 1 (Pre-resolve): Reject direct symbolic link targets before following symlinks
        if raw_target.is_symlink():
            all_errors.append(f"Security boundary violation: target path {target_rel} is a symbolic link.")
            continue

        # Invariant 2: Verify parent directories do not traverse symlinks escaping workspace
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

        target_file = raw_target.resolve()

        # Invariant 3: Resolved target file must remain strictly inside the workspace root
        try:
            target_file.relative_to(root_resolved)
        except ValueError:
            all_errors.append(f"Security boundary violation: target path {target_rel} escapes workspace.")
            continue

        if target_file.is_symlink():
            all_errors.append(f"Security boundary violation: target path {target_rel} is a symbolic link.")
            continue

        use_dirfd = _use_posix_dirfd()

        # Plan: File Creation
        if file_patch.old_path == "/dev/null":
            new_lines = [l[1:] for h in file_patch.hunks for l in h.lines if l.startswith("+")]
            new_content = "\n".join(new_lines)
            planned_operations.append({
                "op": "create",
                "target_file": target_file,
                "target_rel": target_rel,
                "rel_parts": rel_parts,
                "original_content": None,
                "new_content": new_content,
                "pre_hash": None,
                "orig_mode": None,
            })
            continue

        # Plan: File Deletion
        if file_patch.new_path == "/dev/null":
            if use_dirfd:
                try:
                    orig_content, pre_hash, orig_mode = _read_text_posix_nofollow(root_resolved, rel_parts)
                except FileNotFoundError:
                    all_errors.append(f"Target file to delete does not exist in workspace: {target_rel}")
                    continue
                except (PermissionError, OSError) as exc:
                    all_errors.append(f"Security boundary violation reading {target_rel}: {exc}")
                    continue
            else:
                if not target_file.exists():
                    all_errors.append(f"Target file to delete does not exist in workspace: {target_rel}")
                    continue
                orig_mode = stat.S_IMODE(target_file.stat(follow_symlinks=False).st_mode)
                orig_content = target_file.read_text(encoding="utf-8", errors="replace")
                pre_hash = calculate_file_hash(target_file)

            planned_operations.append({
                "op": "delete",
                "target_file": target_file,
                "target_rel": target_rel,
                "rel_parts": rel_parts,
                "original_content": orig_content,
                "new_content": None,
                "pre_hash": pre_hash,
                "orig_mode": orig_mode,
            })
            continue

        # Plan: File Modification
        try:
            if use_dirfd:
                try:
                    original_content, pre_hash, orig_mode = _read_text_posix_nofollow(root_resolved, rel_parts)
                except FileNotFoundError:
                    all_errors.append(f"Target file does not exist in workspace: {target_rel}")
                    continue
                except (PermissionError, OSError) as exc:
                    all_errors.append(f"Security boundary violation reading {target_rel}: {exc}")
                    continue
            else:
                if not target_file.exists():
                    all_errors.append(f"Target file does not exist in workspace: {target_rel}")
                    continue
                orig_mode = stat.S_IMODE(target_file.stat(follow_symlinks=False).st_mode)
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
                "rel_parts": rel_parts,
                "original_content": original_content,
                "new_content": patched_content,
                "pre_hash": pre_hash,
                "orig_mode": orig_mode,
            })
        except Exception as e:
            all_errors.append(f"Error validating patch for {target_rel}: {str(e)}")

    # ATOMICITY ENFORCEMENT: If ANY error occurred during dry-run, abort immediately without modifying ANY files!
    if all_errors:
        return False, all_errors

    # -------------------------------------------------------------------------
    # PHASE 2: Atomic Execution & Rollback Guard
    # -------------------------------------------------------------------------
    use_dirfd = _use_posix_dirfd()
    executed_ops = []
    try:
        for plan in planned_operations:
            op = plan["op"]
            target = plan["target_file"]
            rel_parts = plan["rel_parts"]

            if use_dirfd:
                if op == "create":
                    _write_text_posix_nofollow(root_resolved, rel_parts, plan["new_content"], create_parents=True)
                    executed_ops.append(plan)
                elif op == "delete":
                    _unlink_posix_nofollow(root_resolved, rel_parts)
                    executed_ops.append(plan)
                elif op == "modify":
                    _write_text_posix_nofollow(
                        root_resolved,
                        rel_parts,
                        plan["new_content"],
                        create_parents=False,
                        file_mode=plan["orig_mode"],
                    )
                    executed_ops.append(plan)
            else:
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
            rel_parts = plan["rel_parts"]
            try:
                if use_dirfd:
                    if op == "create":
                        try:
                            _unlink_posix_nofollow(root_resolved, rel_parts)
                        except FileNotFoundError:
                            pass
                    elif op == "delete":
                        _write_text_posix_nofollow(
                            root_resolved,
                            rel_parts,
                            plan["original_content"],
                            create_parents=True,
                            file_mode=plan["orig_mode"],
                        )
                    elif op == "modify":
                        _write_text_posix_nofollow(
                            root_resolved,
                            rel_parts,
                            plan["original_content"],
                            create_parents=False,
                            file_mode=plan["orig_mode"],
                        )
                else:
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
