"""Bounded access to the local Mycelium control protocol.

The node owns content addressing, storage and peer transport. This client never
substitutes an HTTP service or a local database for those responsibilities.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import time

MAX_FRAME = 1024 * 1024
MAX_ARTIFACT = 128 * 1024
CID = re.compile(r"(?:Qm)?[0-9a-fA-F]{64}\Z")


class ProtocolError(ValueError):
    pass


class MutationUncertain(RuntimeError):
    """The node may have committed; callers must reconcile before retrying."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def valid_cid(value):
    return isinstance(value, str) and CID.fullmatch(value) is not None


class ControlClient:
    def __init__(self, path):
        self.path = Path(path)

    def request(self, command, mutation=False):
        token = os.environ.get("MYCELIUM_CONTROL_TOKEN", "").strip()
        if not token:
            token = (self.path.parent / "control.token").read_text().strip()
        if not token:
            raise ProtocolError("missing control token")
        frame = (canonical({**command, "auth": token}) + "\n").encode()
        if len(frame) > MAX_FRAME:
            raise ProtocolError("request exceeds frame limit")
        sent = False
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(3)
                sock.connect(str(self.path))
                # A partial send can also commit; mark uncertainty before sendall.
                sent = True
                sock.sendall(frame)
                deadline = time.monotonic() + 3
                reply = bytearray()
                while b"\n" not in reply:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ProtocolError("control deadline exceeded")
                    sock.settimeout(remaining)
                    part = sock.recv(min(65536, MAX_FRAME + 1 - len(reply)))
                    if not part:
                        raise ProtocolError("unterminated control response")
                    reply.extend(part)
                    if len(reply) > MAX_FRAME:
                        raise ProtocolError("response exceeds frame limit")
                line, trailing = bytes(reply).split(b"\n", 1)
                if trailing.strip():
                    raise ProtocolError("unexpected trailing response")
                result = json.loads(line)
                if not isinstance(result, dict) or not isinstance(result.get("status"), str):
                    raise ProtocolError("invalid control response")
                if result["status"] == "err":
                    # A generic node error does not prove an earlier persistence
                    # step did not commit. Mutations remain uncertain.
                    raise ProtocolError("node rejected command")
                return result
        except (OSError, ValueError, UnicodeError) as error:
            if mutation and sent:
                raise MutationUncertain("publication requires reconciliation") from error
            raise

    def publish(self, leaves, message):
        result = self.request({"cmd": "repo_publish", "repository": None,
                               "branch": None, "expected_previous_cid": None,
                               "message": message, "leaves": leaves}, mutation=True)
        expected_bytes = sum(len(leaf["content"]) for leaf in leaves)
        if (result.get("status") != "repo_published" or not valid_cid(result.get("cid"))
                or type(result.get("leaves")) is not int or result["leaves"] != len(leaves)
                or type(result.get("bytes")) is not int or result["bytes"] != expected_bytes):
            raise MutationUncertain("invalid publication acknowledgement")
        return result["cid"]

    def clone(self, cid):
        if not valid_cid(cid):
            raise ProtocolError("invalid native content ID")
        result = self.request({"cmd": "repo_clone", "cid": cid})
        if result.get("status") != "repo_clone_result" or not isinstance(result.get("leaves"), list):
            raise ProtocolError("invalid clone response")
        return result["leaves"]


def leaf(path, data):
    if (not isinstance(path, str) or not path or len(path) > 255
            or Path(path).name != path or path in (".", "..")
            or not isinstance(data, bytes) or len(data) > MAX_ARTIFACT):
        raise ProtocolError("invalid bounded leaf")
    return {"path": path, "content": list(data)}


def task_leaves(data, name):
    if not isinstance(data, bytes) or len(data) > MAX_ARTIFACT:
        raise ProtocolError("artifact exceeds local task limit")
    if not isinstance(name, str) or not name or len(name) > 255 or Path(name).name != name or name in (".", ".."):
        raise ProtocolError("invalid artifact name")
    manifest = {"schema": "mycelium.artifact_verify.v1", "name": name,
                "path": "artifact.bin", "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest()}
    return [leaf("task.json", canonical(manifest).encode()), leaf("artifact.bin", data)]


def verify_task(leaves):
    if not isinstance(leaves, list) or len(leaves) != 2:
        raise ProtocolError("task must contain exactly two leaves")
    decoded = {}
    for item in leaves:
        if not isinstance(item, dict) or set(item) != {"path", "content"}:
            raise ProtocolError("invalid leaf")
        path, content = item["path"], item["content"]
        limit = 4096 if path == "task.json" else MAX_ARTIFACT
        if (not isinstance(path, str) or path not in ("task.json", "artifact.bin") or path in decoded
                or not isinstance(content, list) or len(content) > limit
                or any(type(byte) is not int or not 0 <= byte <= 255 for byte in content)):
            raise ProtocolError("invalid leaf path or bytes")
        decoded[path] = bytes(content)
    try:
        manifest = json.loads(decoded["task.json"])
    except (ValueError, UnicodeError) as error:
        raise ProtocolError("invalid manifest encoding") from error
    if not isinstance(manifest, dict) or set(manifest) != {"schema", "name", "path", "bytes", "sha256"}:
        raise ProtocolError("invalid manifest")
    data = decoded["artifact.bin"]
    expected = json.loads(bytes(task_leaves(data, manifest.get("name"))[0]["content"]))
    if type(manifest.get("bytes")) is not int or manifest != expected:
        raise ProtocolError("artifact integrity mismatch")
    return {"schema": "mycelium.artifact_receipt.v1", "accepted": True,
            "artifact_sha256": expected["sha256"], "artifact_bytes": len(data),
            "validation": "bounded manifest and SHA-256", "received_revenue": False}
