from __future__ import annotations

from configparser import ConfigParser, Error as ConfigParserError
from hashlib import sha256
from io import StringIO
from pathlib import Path

from nodetrace_ir.contracts import CollectionContext, EvidenceDraft, GapDraft, RelationDraft, utc_now

from . import helpers
from ._common import as_dict, cancelled_gap, finish, iso_from_timestamp, new_result, powershell_gap, text


def _zone_transfer_fields(content: str) -> dict[str, str]:
    """Extract bounded Mark-of-the-Web fields without following either URL."""

    if not content or len(content) > 65536:
        return {}
    parser = ConfigParser(interpolation=None, strict=False)
    try:
        parser.read_file(StringIO(content))
    except (ConfigParserError, OSError, UnicodeError):
        return {}
    if not parser.has_section("ZoneTransfer"):
        return {}
    section = parser["ZoneTransfer"]
    result: dict[str, str] = {}
    for source_name, target_name in (
        ("ZoneId", "zone_id"),
        ("HostUrl", "host_url"),
        ("ReferrerUrl", "referrer_url"),
    ):
        value = str(section.get(source_name, "")).strip()
        if value and len(value) <= 8192 and not any(ch in value for ch in "\x00\r\n"):
            result[target_name] = value
    return result


def _storage_location_fields(value: object) -> dict[str, object]:
    """Normalize the bounded, read-only Windows storage inventory payload."""

    payload = as_dict(value)
    fields: dict[str, object] = {}
    for source_name, target_name in (
        ("DriveLetter", "drive_letter"),
        ("DriveTypeName", "drive_type_name"),
        ("VolumeLabel", "volume_label"),
        ("FileSystem", "file_system"),
        ("VolumeSerialNumber", "volume_serial_number"),
        ("VolumeGuid", "volume_guid"),
        ("DiskModel", "disk_model"),
        ("DiskInterfaceType", "disk_interface_type"),
        ("DiskMediaType", "disk_media_type"),
        ("PNPDeviceID", "pnp_device_id"),
        ("DeviceSerialNumber", "device_serial_number"),
        ("DiskDeviceID", "disk_device_id"),
    ):
        normalized = text(payload.get(source_name)).strip()
        if normalized and len(normalized) <= 8192 and not any(ch in normalized for ch in "\x00\r\n"):
            fields[target_name] = normalized

    try:
        fields["drive_type"] = int(payload.get("DriveType"))
    except (TypeError, ValueError):
        pass
    if fields:
        try:
            fields["physical_disk_count"] = max(0, int(payload.get("PhysicalDiskCount")))
        except (TypeError, ValueError):
            pass
    return fields


def _is_current_removable_or_usb_storage(fields: dict[str, object]) -> tuple[bool, list[str]]:
    """Classify only the file's observed current storage, never its delivery history."""

    basis: list[str] = []
    if fields.get("drive_type") == 2:
        basis.append("Win32_LogicalDisk.DriveType=2 (removable disk)")
    interface_type = str(fields.get("disk_interface_type", "")).strip().casefold()
    if interface_type == "usb":
        basis.append("Win32_DiskDrive.InterfaceType=USB")
    pnp_device_id = str(fields.get("pnp_device_id", "")).strip().upper()
    if pnp_device_id.startswith("USBSTOR\\") or pnp_device_id.startswith("USB\\"):
        basis.append("Win32_DiskDrive.PNPDeviceID identifies a USB device")
    media_type = str(fields.get("disk_media_type", "")).strip().casefold()
    if "removable" in media_type:
        basis.append("Win32_DiskDrive.MediaType identifies removable media")
    return bool(basis), basis


class FileSeedCollector:
    name = "file_seed"
    display_name = "Suspect file fingerprint"
    supports_offline = True

    _WINDOWS_METADATA_SCRIPT = r"""
$target = $env:NODETRACE_TARGET
$expectedSha256 = $env:NODETRACE_EXPECTED_SHA256
$metadataSha256 = $null
$identityError = $null
$zone = [ordered]@{ Present = $false; Content = $null; Length = $null; Error = $null }
$signature = $null
$signatureError = $null
$storage = [ordered]@{
    DriveLetter = $null
    DriveType = $null
    DriveTypeName = $null
    VolumeLabel = $null
    FileSystem = $null
    VolumeSerialNumber = $null
    VolumeGuid = $null
    DiskModel = $null
    DiskInterfaceType = $null
    DiskMediaType = $null
    PNPDeviceID = $null
    DeviceSerialNumber = $null
    DiskDeviceID = $null
    PhysicalDiskCount = 0
}
$storageErrors = [System.Collections.Generic.List[string]]::new()

try {
    $metadataSha256 = (Get-FileHash -LiteralPath $target -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    if ($metadataSha256 -ne $expectedSha256.ToLowerInvariant()) {
        $identityError = 'The path resolved to content with a different SHA-256 hash'
    }
} catch {
    $identityError = $_.Exception.Message
}

if (-not $identityError) {
    try {
        $stream = @(
            Get-Item -LiteralPath $target -Stream '*' -ErrorAction Stop |
                Where-Object { $_.Stream -eq 'Zone.Identifier' }
        ) | Select-Object -First 1
        if ($stream) {
            $zone.Present = $true
            $zone.Length = $stream.Length
            $zone.Content = Get-Content -LiteralPath $target -Stream 'Zone.Identifier' -Raw -ErrorAction Stop
        }
    } catch {
        $zone.Error = $_.Exception.Message
    }

    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $target -ErrorAction Stop
        $signature = [ordered]@{
            Status = [string]$sig.Status
            StatusMessage = $sig.StatusMessage
            SignatureType = [string]$sig.SignatureType
            IsOSBinary = $sig.IsOSBinary
            SignerSubject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
            SignerIssuer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Issuer } else { $null }
            SignerThumbprint = if ($sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { $null }
            SignerNotBefore = if ($sig.SignerCertificate) { $sig.SignerCertificate.NotBefore.ToUniversalTime().ToString('o') } else { $null }
            SignerNotAfter = if ($sig.SignerCertificate) { $sig.SignerCertificate.NotAfter.ToUniversalTime().ToString('o') } else { $null }
            TimestampThumbprint = if ($sig.TimeStamperCertificate) { $sig.TimeStamperCertificate.Thumbprint } else { $null }
        }
    } catch {
        $signatureError = $_.Exception.Message
    }

    try {
        $item = Get-Item -LiteralPath $target -ErrorAction Stop
        $driveLetter = [System.IO.Path]::GetPathRoot($item.FullName).TrimEnd('\\')
        $logical = @(
            Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction Stop |
                Where-Object { [string]$_.DeviceID -ieq $driveLetter }
        ) | Select-Object -First 1
        if (-not $logical) {
            throw "No Win32_LogicalDisk instance matched $driveLetter"
        }

        $storage.DriveLetter = [string]$logical.DeviceID
        $storage.DriveType = [int]$logical.DriveType
        $storage.DriveTypeName = switch ([int]$logical.DriveType) {
            0 { 'Unknown' }
            1 { 'NoRootDirectory' }
            2 { 'Removable' }
            3 { 'LocalDisk' }
            4 { 'NetworkDrive' }
            5 { 'CompactDisc' }
            6 { 'RamDisk' }
            default { 'Unrecognized' }
        }
        $storage.VolumeLabel = [string]$logical.VolumeName
        $storage.FileSystem = [string]$logical.FileSystem
        $storage.VolumeSerialNumber = [string]$logical.VolumeSerialNumber

        try {
            $volume = @(
                Get-CimInstance -ClassName Win32_Volume -ErrorAction Stop |
                    Where-Object { [string]$_.DriveLetter -ieq $storage.DriveLetter }
            ) | Select-Object -First 1
            if ($volume) {
                $storage.VolumeGuid = [string]$volume.DeviceID
                if (-not $storage.VolumeLabel) { $storage.VolumeLabel = [string]$volume.Label }
                if (-not $storage.FileSystem) { $storage.FileSystem = [string]$volume.FileSystem }
                if (-not $storage.VolumeSerialNumber) {
                    $storage.VolumeSerialNumber = [string]$volume.SerialNumber
                }
            }
        } catch {
            $storageErrors.Add("Win32_Volume: $($_.Exception.Message)")
        }

        try {
            $partitions = @(
                Get-CimAssociatedInstance -InputObject $logical `
                    -Association Win32_LogicalDiskToPartition -ErrorAction Stop
            )
            $physicalDisks = @(
                foreach ($partition in $partitions) {
                    Get-CimAssociatedInstance -InputObject $partition `
                        -Association Win32_DiskDriveToDiskPartition -ErrorAction Stop
                }
            ) | Sort-Object -Property DeviceID -Unique
            $storage.PhysicalDiskCount = @($physicalDisks).Count
            $disk = @($physicalDisks) | Select-Object -First 1
            if ($disk) {
                $storage.DiskModel = [string]$disk.Model
                $storage.DiskInterfaceType = [string]$disk.InterfaceType
                $storage.DiskMediaType = [string]$disk.MediaType
                $storage.PNPDeviceID = [string]$disk.PNPDeviceID
                $storage.DeviceSerialNumber = ([string]$disk.SerialNumber).Trim()
                $storage.DiskDeviceID = [string]$disk.DeviceID
            }
        } catch {
            $storageErrors.Add("Win32_DiskDrive association: $($_.Exception.Message)")
        }
    } catch {
        $storageErrors.Add("Current storage location: $($_.Exception.Message)")
    }
}

[ordered]@{
    MetadataSha256 = $metadataSha256
    IdentityError = $identityError
    ZoneIdentifier = $zone
    Signature = $signature
    SignatureError = $signatureError
    StorageLocation = $storage
    StorageError = if ($storageErrors.Count -gt 0) { $storageErrors -join '; ' } else { $null }
} |
    ConvertTo-Json -Depth 8 -Compress
"""

    def collect(self, context: CollectionContext):
        started_at = utc_now()
        result = new_result(self.name, started_at)
        if context.cancel_event.is_set():
            result.gaps.append(cancelled_gap(self.name))
            return finish(result)

        path = Path(context.suspect_path).expanduser()
        ps: helpers.PowerShellResult | None = None
        try:
            with helpers.open_verified_evidence_file(path) as opened:
                stat = opened.initial_stat
                resolved_path = str(opened.path)
                hashes = opened.hashes()
                if helpers.is_windows():
                    ps = helpers.run_powershell_json(
                        self._WINDOWS_METADATA_SCRIPT,
                        timeout=20,
                        env={
                            "NODETRACE_TARGET": resolved_path,
                            "NODETRACE_EXPECTED_SHA256": hashes["sha256"],
                        },
                    )
        except helpers.UnsafeEvidencePathError as exc:
            result.gaps.append(
                GapDraft(
                    collector=self.name,
                    source=str(path),
                    reason=f"Unsafe suspect path was rejected: {exc}",
                    impact="The seed artifact was not opened or fingerprinted",
                    recommendation=(
                        "Use an absolute path to a regular file on a directly attached local volume; "
                        "do not use UNC, device, alternate-stream, symlink, junction, or other reparse paths"
                    ),
                )
            )
            return finish(result, failed=True)
        except helpers.EvidenceFileChangedError as exc:
            result.gaps.append(
                GapDraft(
                    collector=self.name,
                    source=str(path),
                    reason=f"Suspect file changed during acquisition: {exc}",
                    impact="Hashes and path-based metadata cannot be treated as one stable artifact",
                    recommendation="Acquire a preserved read-only copy and retry the collection",
                )
            )
            return finish(result, failed=True)
        except OSError as exc:
            result.gaps.append(
                GapDraft(
                    collector=self.name,
                    source=str(path),
                    reason=f"Suspect file could not be opened or read safely: {exc}",
                    impact="The artifact cannot be reliably fingerprinted or correlated",
                    recommendation="Preserve the file on a local read-only evidence volume and retry",
                )
            )
            return finish(result, failed=True)

        file_key = f"file:sha256:{hashes['sha256']}"
        properties = {
            "is_seed": True,
            "path": resolved_path,
            "name": path.name,
            "extension": path.suffix.lower(),
            "size": stat.st_size,
            "sha256": hashes["sha256"],
            "sha1": hashes["sha1"],
            "md5": hashes["md5"],
            "created_utc": iso_from_timestamp(stat.st_ctime),
            "modified_utc": iso_from_timestamp(stat.st_mtime),
            "accessed_utc": iso_from_timestamp(stat.st_atime),
        }
        seed = EvidenceDraft(
            entity_type="file",
            label=path.name,
            observed_at=properties["modified_utc"],
            source="filesystem seed",
            stable_key=file_key,
            source_ref=resolved_path,
            confidence="high",
            properties=properties,
            raw={"stat_size": stat.st_size, "stat_mode": stat.st_mode},
        )
        result.evidence.append(seed)

        if not helpers.is_windows():
            result.gaps.append(
                GapDraft(
                    collector=self.name,
                    source="NTFS alternate streams and Windows Authenticode",
                    reason="Windows metadata is unavailable on this operating system",
                    impact="Mark-of-the-Web and signature state were not collected",
                    recommendation="Run this collector against the preserved artifact on Windows/NTFS",
                )
            )
            result.raw_payload = {"hashes": hashes}
            return finish(result)

        assert ps is not None
        if not ps.ok:
            if (
                str(context.options.get("target_mode") or "live").casefold() == "offline"
                and bool(context.options.get("winpe"))
            ):
                result.gaps.append(
                    GapDraft(
                        collector=self.name,
                        source="Zone.Identifier, Authenticode and current storage identity",
                        reason=f"Windows metadata enrichment was unavailable in WinPE: {ps.error}",
                        impact=(
                            "The file hashes and basic filesystem metadata were collected, but Mark-of-the-Web, "
                            "signature state and current device identity are incomplete"
                        ),
                        recommendation=(
                            "Analyze the same preserved file from a supported full Windows technician host, or "
                            "include and validate the required WinPE PowerShell/WMI optional components"
                        ),
                    )
                )
            else:
                result.gaps.append(powershell_gap(self.name, "Zone.Identifier and Authenticode", ps.error))
            result.raw_payload = {"hashes": hashes, "powershell_error": ps.error}
            return finish(result)

        payload = as_dict(ps.data)
        metadata_sha256 = text(payload.get("MetadataSha256")).strip().lower()
        identity_error = text(payload.get("IdentityError")).strip()
        if identity_error or metadata_sha256 != hashes["sha256"]:
            reason = identity_error or "PowerShell metadata query did not return the expected SHA-256"
            result.gaps.append(
                GapDraft(
                    collector=self.name,
                    source="Zone.Identifier and Authenticode",
                    reason=f"Path identity check failed before metadata was accepted: {reason}",
                    impact="Zone.Identifier and signature data were discarded because they may belong to another file",
                    recommendation="Acquire a stable read-only copy and retry metadata collection",
                )
            )
            result.raw_payload = {
                "hashes": hashes,
                "metadata_sha256": metadata_sha256,
                "identity_error": identity_error,
            }
            return finish(result)
        zone = as_dict(payload.get("ZoneIdentifier"))
        signature = as_dict(payload.get("Signature"))
        storage_payload = as_dict(payload.get("StorageLocation"))
        storage = _storage_location_fields(storage_payload)
        seed.properties["zone_identifier_present"] = bool(zone.get("Present"))
        seed.properties["signature_status"] = text(signature.get("Status")) or "unknown"

        if storage:
            seed.properties["current_storage"] = storage
            seed.properties["current_storage_observed_at"] = started_at
            is_removable_or_usb, classification_basis = _is_current_removable_or_usb_storage(storage)
            if is_removable_or_usb:
                identity = "\x1f".join(
                    str(storage.get(field, ""))
                    for field in (
                        "pnp_device_id",
                        "device_serial_number",
                        "volume_guid",
                        "volume_serial_number",
                        "disk_device_id",
                        "drive_letter",
                    )
                )
                media_key = f"removable_media:{sha256(identity.encode('utf-8')).hexdigest()}"
                media_label = text(storage.get("disk_model")).strip()
                if not media_label:
                    media_label = text(storage.get("volume_label")).strip()
                drive_letter = text(storage.get("drive_letter")).strip()
                if not media_label:
                    media_label = "Removable media"
                if drive_letter:
                    media_label = f"{media_label} ({drive_letter})"
                visible_identifier = (
                    text(storage.get("device_serial_number")).strip()
                    or text(storage.get("volume_serial_number")).strip()
                    or text(storage.get("pnp_device_id")).strip()
                    or text(storage.get("volume_guid")).strip()
                )
                if visible_identifier:
                    media_label = f"USB {visible_identifier} · {media_label}"
                result.evidence.append(
                    EvidenceDraft(
                        entity_type="removable_media",
                        label=media_label,
                        observed_at=started_at,
                        source="Windows CIM storage inventory",
                        stable_key=media_key,
                        source_ref=(
                            text(storage.get("pnp_device_id")).strip()
                            or text(storage.get("volume_guid")).strip()
                            or drive_letter
                        ),
                        confidence="high",
                        properties={
                            **storage,
                            "classification_basis": classification_basis,
                            "current_location_only": True,
                            "historical_delivery_proven": False,
                        },
                        raw=storage_payload,
                    )
                )
                result.relations.append(
                    RelationDraft(
                        source_key=media_key,
                        target_key=file_key,
                        relation_type="present_on_removable_media",
                        confidence="high",
                        rationale=(
                            "The suspect file was observed on this removable or USB-backed device "
                            "during collection. This proves only its current location and does not "
                            "prove that the file was historically delivered or copied from this device."
                        ),
                        observed_at=started_at,
                    )
                )

        if zone.get("Present"):
            zone_content = text(zone.get("Content"))
            zone_fields = _zone_transfer_fields(zone_content)
            seed.properties.update(zone_fields)
            zone_key = f"ads:zone_identifier:{hashes['sha256']}"
            result.evidence.append(
                EvidenceDraft(
                    entity_type="alternate_data_stream",
                    label=f"{path.name}:Zone.Identifier",
                    observed_at=properties["modified_utc"],
                    source="NTFS Zone.Identifier",
                    stable_key=zone_key,
                    source_ref=f"{resolved_path}:Zone.Identifier",
                    confidence="high",
                    properties={
                        "stream_name": "Zone.Identifier",
                        "length": zone.get("Length"),
                        "content": zone_content,
                        **zone_fields,
                    },
                    raw=zone,
                )
            )
            result.relations.append(
                RelationDraft(
                    source_key=file_key,
                    target_key=zone_key,
                    relation_type="has_alternate_stream",
                    confidence="high",
                    rationale="Zone.Identifier was read directly from the suspect file's NTFS stream",
                    observed_at=properties["modified_utc"],
                )
            )
            seen_origins: set[str] = set()
            for role, field in (("HostUrl", "host_url"), ("ReferrerUrl", "referrer_url")):
                url = zone_fields.get(field, "")
                normalized_url = url.casefold()
                if not url or normalized_url in seen_origins:
                    continue
                seen_origins.add(normalized_url)
                origin_key = (
                    f"download_origin:{role.casefold()}:"
                    f"{sha256(url.encode('utf-8', errors='surrogatepass')).hexdigest()}"
                )
                result.evidence.append(
                    EvidenceDraft(
                        entity_type="download_origin",
                        label=url,
                        observed_at=properties["modified_utc"],
                        source="NTFS Zone.Identifier",
                        stable_key=origin_key,
                        source_ref=f"{resolved_path}:Zone.Identifier#{role}",
                        confidence="medium",
                        properties={
                            "url": url,
                            "origin_role": role,
                            "reported_by": "Zone.Identifier",
                            "mutable_metadata": True,
                        },
                        raw={"field": role, "value": url},
                    )
                )
                result.relations.append(
                    RelationDraft(
                        source_key=origin_key,
                        target_key=file_key,
                        relation_type="reported_download_source",
                        confidence="medium",
                        rationale=(
                            f"Zone.Identifier {role} names this location for the file; "
                            "the alternate stream is mutable and does not by itself prove delivery."
                        ),
                        observed_at=properties["modified_utc"],
                    )
                )
        if zone.get("Error"):
            result.gaps.append(powershell_gap(self.name, "NTFS Zone.Identifier", text(zone["Error"])))

        if signature:
            signature_key = f"authenticode:{hashes['sha256']}"
            result.evidence.append(
                EvidenceDraft(
                    entity_type="authenticode_signature",
                    label=f"Authenticode: {signature.get('Status', 'Unknown')}",
                    observed_at=started_at,
                    source="Get-AuthenticodeSignature",
                    stable_key=signature_key,
                    source_ref=resolved_path,
                    confidence="high",
                    properties=signature,
                    raw=signature,
                )
            )
            result.relations.append(
                RelationDraft(
                    source_key=file_key,
                    target_key=signature_key,
                    relation_type="has_signature_state",
                    confidence="high",
                    rationale="Signature state was queried read-only with Get-AuthenticodeSignature",
                    observed_at=started_at,
                )
            )
        if payload.get("SignatureError"):
            result.gaps.append(
                powershell_gap(self.name, "Get-AuthenticodeSignature", text(payload["SignatureError"]))
            )
        if payload.get("StorageError"):
            result.gaps.append(
                GapDraft(
                    collector=self.name,
                    source="Windows volume and physical-disk inventory",
                    reason=text(payload["StorageError"]),
                    impact=(
                        "The current volume or physical-device identity may be incomplete; no historical "
                        "USB delivery inference is made from missing storage telemetry"
                    ),
                    recommendation="Run elevated on the original Windows host and preserve CIM access logs",
                )
            )

        result.raw_payload = payload
        return finish(result)
