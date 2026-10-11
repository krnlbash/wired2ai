"""Bounded encoding, public-parameter, and key-container triage."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
from collections import Counter

from .files import FileInput, contains_private_key
from .report import Report
from .runner import Runner


def byte_statistics(data: bytes) -> dict:
    sample = data[:1048576]
    counts = Counter(sample)
    entropy = -sum((count / len(sample)) * math.log2(count / len(sample)) for count in counts.values()) if sample else 0.0
    return {"sample_offset": 0, "sample_bytes": len(sample), "total_bytes": len(data),
            "shannon_entropy_bits_per_byte": round(entropy, 5),
            "printable_ascii_fraction": round(sum(32 <= byte < 127 for byte in sample) / len(sample), 5) if sample else 0,
            "unique_byte_values": len(counts), "sample_truncated": len(sample) != len(data),
            "interpretation": "Descriptive statistics only; high entropy does not identify encryption, compression, or a cipher."}


def encoding_candidates(data: bytes) -> dict:
    sample = data[:65536]
    text = sample.decode("ascii", "replace")
    candidates = []
    # One decoding layer. No execution, file creation, or recursive decompression.
    for match in re.finditer(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{8,}(?![A-Za-z0-9+/=_-])", text):
        token = match.group()
        if len(token) > 32768:
            continue
        variants = []
        if re.fullmatch(r"[0-9a-fA-F]+", token) and len(token) % 2 == 0:
            variants.append(("hex", bytes.fromhex(token)))
        if len(token) % 4 == 0:
            try:
                decoded = base64.b64decode(token, altchars=b"-_", validate=True)
                # Ensure canonical padding/unused bits, not merely permissive decoding.
                canonical = base64.b64encode(decoded).decode()
                if canonical == token.translate(str.maketrans("-_", "+/")):
                    variants.append(("base64", decoded))
            except (ValueError, binascii.Error):
                pass
        for encoding, decoded in variants:
            preview = "[SUPPRESSED PRIVATE KEY]" if contains_private_key(decoded) else decoded[:160].decode("utf-8", "replace")
            candidates.append({"encoding": encoding, "source_offset": match.start(), "source_length": len(token),
                               "decoded_length": len(decoded), "decoded_sha256": hashlib.sha256(decoded).hexdigest(),
                               "decoded_preview": preview, "preview_truncated": len(decoded) > 160})
            if len(candidates) >= 12:
                return {"candidates": candidates, "selection_truncated": True, "sample_bytes": len(sample)}
    return {"candidates": candidates, "selection_truncated": len(data) > len(sample), "sample_bytes": len(sample),
            "note": "Encoding compatibility is not proof of intended encoding; unpadded base64 is not inferred."}


def rsa_parameters(data: bytes) -> dict:
    if len(data) > 1048576:
        return {"parameters": {}, "reason": "Text parameter parser limited to 1 MiB"}
    text = data.decode("utf-8", "replace")
    values = {}
    locations = {}
    duplicate_json_keys = []

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                duplicate_json_keys.append(key)
            result[key] = value
        return result

    try:
        parsed = json.loads(text, object_pairs_hook=unique_object)
    except (ValueError, RecursionError):
        parsed = None
    if duplicate_json_keys:
        return {"parameters": {}, "reason": "Duplicate JSON keys are ambiguous; parameter analysis skipped",
                "duplicate_json_keys": duplicate_json_keys[:20]}
    if isinstance(parsed, dict):
        entries = [(key, parsed[key], f"$.{key}") for key in ("n", "e", "c") if key in parsed]
    else:
        entries = []
        for line_number, line in enumerate(text.splitlines(), 1):
            match = re.fullmatch(r"\s*([nec])\s*[:=]\s*(0x[0-9a-fA-F]+|[0-9]+)\s*", line)
            if match:
                entries.append((match[1], match[2], f"line {line_number}"))
    duplicates = []
    for key, value, location in entries:
        if key in values:
            duplicates.append(key)
            continue
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            continue
        representation = str(value)
        if len(representation) > 4096 or not re.fullmatch(r"(?:0x[0-9a-fA-F]+|[0-9]+)", representation):
            continue
        values[key] = int(representation, 16 if representation.startswith("0x") else 10)
        locations[key] = location
    findings = []
    n, e, c = values.get("n"), values.get("e"), values.get("c")
    if n is not None:
        if n <= 1:
            findings.append("n is not a valid positive RSA modulus greater than 1")
        else:
            if n % 2 == 0:
                findings.append("n is even; divisibility by 2 observed")
            if math.isqrt(n) ** 2 == n:
                findings.append("n is a perfect square")
            if e is not None:
                if e <= 1 or e >= n:
                    findings.append("e is outside the conventional 1 < e < n range")
                divisor = math.gcd(e, n)
                if 1 < divisor < n:
                    findings.append(f"gcd(e, n) reveals a nontrivial divisor: {divisor}")
            if c is not None and c >= n:
                findings.append("c is outside the usual ciphertext representative range 0 <= c < n")
    if e is not None and e in {3, 5, 7}:
        findings.append("Small public exponent observed; exploitation depends on padding and message conditions")
    return {"parameters": {key: {"decimal": str(value), "bits": value.bit_length(), "source": locations[key]}
                           for key, value in values.items()}, "observations": findings,
            "duplicate_assignments_ignored": duplicates,
            "limits": "Only literal n/e/c in flat JSON or assignment lines. No eval, import, factoring, or padding verification."}


def collect_crypto(report: Report, source: FileInput, runner: Runner) -> None:
    stats = byte_statistics(source.data)
    report.add("K001", "Byte distribution", "partial" if stats["sample_truncated"] else "complete", stats, refs=["E001"])
    if source.profile["private_key_marker"]:
        report.add("K002", "Encoding candidates", "skipped", notes=["Private-key container: payload previews suppressed."])
        report.add("K003", "Literal RSA parameter checks", "skipped", notes=["Private-key container: only public-component export is attempted."])
    else:
        encodings = encoding_candidates(source.data)
        report.add("K002", "Encoding candidates", "partial" if encodings["selection_truncated"] else
                   ("complete" if encodings["candidates"] else "no_match"), encodings, refs=["E001"])
        params = rsa_parameters(source.data)
        report.add("K003", "Literal RSA parameter checks", "complete" if params["parameters"] else
                   ("skipped" if "reason" in params else "no_match"), params, refs=["E001"])
    data = source.data
    if b"-----BEGIN ENCRYPTED PRIVATE KEY-----" in data or re.search(rb"Proc-Type:\s*4,ENCRYPTED", data, re.I):
        report.add("K004", "PEM public components or certificate metadata", "skipped",
                   notes=["Encrypted private-key container detected; no passphrase request or decryption attempt."])
        return
    if b"-----BEGIN CERTIFICATE-----" in data:
        args = ["openssl", "x509", "-in", str(source.path), "-noout", "-subject", "-issuer", "-dates", "-serial"]
    elif re.search(rb"-----BEGIN (?:RSA )?PUBLIC KEY-----", data) or source.profile["private_key_marker"]:
        args = ["openssl", "pkey", "-in", str(source.path), "-noout", "-text_pub", "-passin", "pass:"]
        if not source.profile["private_key_marker"]:
            args.append("-pubin")
    else:
        report.add("K004", "PEM public components or certificate metadata", "not_applicable",
                   notes=["Supported: PEM public/private keys and X.509 certificates. DER and OpenSSH containers are not inferred."])
        return
    result, ref = report.command(runner, args, source.workdir)
    report.add("K004", "PEM public components or certificate metadata", result.status,
               {"public_description": result.stdout}, refs=[ref],
               notes=["Public components only. No certificate trust validation. Encrypted keys are not unlocked or prompted for."])
