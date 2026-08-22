"""Deterministic FFmpeg media generator and ffprobe inspector.

This is the executable local/CI adapter. Production ComfyUI/Piper adapters
implement the same MediaJobRequest -> MediaJobResult contract.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from forge.contracts.contracts import (
    ArtifactProvenance,
    ArtifactRef,
    MediaJobRequest,
    MediaJobResult,
    MediaObservation,
    ToolKind,
)

if TYPE_CHECKING:
    from forge.artifacts import ArtifactStore


class FFmpegFixtureAdapter:
    adapter_name = "ffmpeg-fixture"
    adapter_version = "1"

    def __init__(self, store: ArtifactStore) -> None:
        self.store = store
        self._artifacts: dict[str, ArtifactRef] = {}

    def execute(self, request: MediaJobRequest) -> tuple[MediaJobResult, list[ArtifactProvenance]]:
        with tempfile.TemporaryDirectory(prefix="forge-media-") as tmp:
            root = Path(tmp)
            if request.operation == ToolKind.IMAGE_GENERATE:
                return self._image(request, root)
            if request.operation == ToolKind.AUDIO_GENERATE:
                return self._audio(request, root)
            if request.operation == ToolKind.VIDEO_GENERATE:
                return self._video(request, root)
            if request.operation == ToolKind.MEDIA_INSPECT:
                return self._inspect(request, root)
        raise ValueError(f"unsupported fixture media operation: {request.operation}")

    def _image(
        self, request: MediaJobRequest, root: Path
    ) -> tuple[MediaJobResult, list[ArtifactProvenance]]:
        out = root / "synthetic.png"
        hue = (request.seed * 37) % 255
        self._run(
            [
                "ffmpeg",
                "-hide_banner",
                "-loglevel",
                "error",
                "-y",
                "-f",
                "lavfi",
                "-i",
                f"color=c=0x{hue:02x}5577:s=640x360:d=1",
                "-frames:v",
                "1",
                str(out),
            ]
        )
        return self._persist(request, out, "image/png", "synthetic_portrait")

    def _audio(
        self, request: MediaJobRequest, root: Path
    ) -> tuple[MediaJobResult, list[ArtifactProvenance]]:
        out = root / "synthetic.wav"
        frequency = 260 + request.seed % 220
        self._run(
            [
                "ffmpeg",
                "-hide_banner",
                "-loglevel",
                "error",
                "-y",
                "-f",
                "lavfi",
                "-i",
                f"sine=frequency={frequency}:duration=3",
                "-ar",
                "16000",
                "-ac",
                "1",
                "-c:a",
                "pcm_s16le",
                str(out),
            ]
        )
        return self._persist(request, out, "audio/wav", "synthetic_voice")

    def _video(
        self, request: MediaJobRequest, root: Path
    ) -> tuple[MediaJobResult, list[ArtifactProvenance]]:
        out = root / "synthetic.mp4"
        inputs = [self._artifacts[x] for x in request.input_artifact_ids]
        image = next((x for x in inputs if x.media_type == "image/png"), None)
        audio = next((x for x in inputs if x.media_type == "audio/wav"), None)
        if image is not None and audio is not None:
            image_path = root / "portrait.png"
            audio_path = root / "voice.wav"
            image_path.write_bytes(self.store.read_bytes(image))
            audio_path.write_bytes(self.store.read_bytes(audio))
            argv = [
                "ffmpeg",
                "-hide_banner",
                "-loglevel",
                "error",
                "-y",
                "-loop",
                "1",
                "-i",
                str(image_path),
                "-i",
                str(audio_path),
                "-shortest",
                "-t",
                "3",
                "-r",
                "24",
                "-vf",
                "scale=640:360,format=yuv420p",
                "-c:v",
                "libx264",
                "-preset",
                "ultrafast",
                "-pix_fmt",
                "yuv420p",
                "-c:a",
                "aac",
                "-metadata",
                "comment=FORGE synthetic fixture",
                str(out),
            ]
        else:
            argv = [
                "ffmpeg",
                "-hide_banner",
                "-loglevel",
                "error",
                "-y",
                "-f",
                "lavfi",
                "-i",
                "testsrc2=size=640x360:rate=24:duration=3",
                "-f",
                "lavfi",
                "-i",
                f"sine=frequency={300 + request.seed % 180}:duration=3",
                "-shortest",
                "-c:v",
                "libx264",
                "-preset",
                "ultrafast",
                "-pix_fmt",
                "yuv420p",
                "-c:a",
                "aac",
                str(out),
            ]
        self._run(argv)
        return self._persist(request, out, "video/mp4", "synthetic_video_call")

    def _inspect(
        self, request: MediaJobRequest, root: Path
    ) -> tuple[MediaJobResult, list[ArtifactProvenance]]:
        if not request.input_artifact_ids:
            raise ValueError("media.inspect requires an artifact id")
        source = self._artifacts.get(request.input_artifact_ids[0])
        if source is None:
            raise FileNotFoundError(request.input_artifact_ids[0])
        path = root / _local_name(source.media_type)
        path.write_bytes(self.store.read_bytes(source))
        raw = subprocess.check_output(
            [
                "ffprobe",
                "-v",
                "error",
                "-show_format",
                "-show_streams",
                "-of",
                "json",
                str(path),
            ],
            text=True,
        )
        probe = cast("dict[str, Any]", json.loads(raw))
        streams = cast("list[dict[str, Any]]", probe.get("streams", []))
        codecs = [str(s.get("codec_name", "unknown")) for s in streams]
        video: dict[str, Any] = next(
            (s for s in streams if s.get("codec_type") == "video"),
            cast("dict[str, Any]", {}),
        )
        audio: dict[str, Any] = next(
            (s for s in streams if s.get("codec_type") == "audio"),
            cast("dict[str, Any]", {}),
        )
        format_data = cast("dict[str, Any]", probe.get("format", {}))
        tags = cast("dict[str, Any]", format_data.get("tags", {}))
        media_type = "video/mp4" if video else "audio/wav"
        artifact = self.store.put_bytes(
            "media-inspected", request.input_artifact_ids[0], path.read_bytes(), media_type
        )
        duration = float(format_data.get("duration", 0) or 0)
        fps = _fraction(str(video.get("avg_frame_rate", "0/1"))) if video else None
        observation = MediaObservation(
            artifact=artifact,
            role=str(request.parameters.get("role", "call_media")),
            observed_at=datetime.now(UTC),
            container=str(format_data.get("format_name", "")),
            codecs=codecs,
            duration_seconds=duration,
            width=int(video.get("width", 0)) or None,
            height=int(video.get("height", 0)) or None,
            frame_rate=fps,
            audio_sample_rate=int(audio.get("sample_rate", 0)) or None,
            encoder_tags={str(k): str(v) for k, v in tags.items()},
            # Fixture detector output is observable evidence, not generation truth.
            decode_warnings=["synthetic_test_pattern_score=0.97"],
        )
        return (
            MediaJobResult(
                job_id=request.job_id,
                status="succeeded",
                output_artifacts=[artifact],
                observations=[observation],
            ),
            [],
        )

    def _persist(
        self,
        request: MediaJobRequest,
        path: Path,
        media_type: str,
        role: str,
    ) -> tuple[MediaJobResult, list[ArtifactProvenance]]:
        artifact_id = f"art_{request.job_id}"
        artifact = self.store.put_bytes("media", artifact_id, path.read_bytes(), media_type)
        self._artifacts[artifact_id] = artifact
        observation = MediaObservation(
            artifact=artifact,
            role=role,
            observed_at=datetime.now(UTC),
        )
        provenance = ArtifactProvenance(
            artifact=artifact,
            cycle_id=request.cycle_id,
            operation_id=request.job_id,
            adapter_name=self.adapter_name,
            adapter_version=self.adapter_version,
            seed=request.seed,
            input_artifact_ids=request.input_artifact_ids,
            tool_versions={"ffmpeg": self._version()},
            generation_parameters=request.parameters,
        )
        return (
            MediaJobResult(
                job_id=request.job_id,
                status="succeeded",
                output_artifacts=[artifact],
                observations=[observation],
            ),
            [provenance],
        )

    def _version(self) -> str:
        return subprocess.check_output(["ffmpeg", "-version"], text=True).splitlines()[0]

    def _run(self, argv: list[str]) -> None:
        subprocess.run(argv, check=True, timeout=60, capture_output=True)


def _fraction(value: str) -> float | None:
    try:
        numerator, denominator = value.split("/", 1)
        return float(numerator) / float(denominator) if float(denominator) else None
    except (ValueError, ZeroDivisionError):
        return None


def _local_name(media_type: str) -> str:
    return {
        "video/mp4": "input.mp4",
        "audio/wav": "input.wav",
        "image/png": "input.png",
    }.get(media_type, "input.bin")
