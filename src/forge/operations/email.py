"""Raw SMTP notifications backed by a durable local outbox adapter."""

from __future__ import annotations

import hashlib
import os
import smtplib
import ssl
from email.message import EmailMessage
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


class EmailNotifier:
    def __init__(self, outbox: Path) -> None:
        self.outbox = outbox
        outbox.mkdir(parents=True, exist_ok=True)

    def send(
        self,
        *,
        notification_type: str,
        run_id: str,
        subject: str,
        body: str,
        dedup_scope: str,
        dry_run: bool = False,
    ) -> Path:
        digest = hashlib.sha256(f"{run_id}:{notification_type}:{dedup_scope}".encode()).hexdigest()[
            :20
        ]
        path = self.outbox / f"{digest}.eml"
        if path.exists():
            return path
        # validate SMTP config before persisting to avoid ghost outbox on KeyError
        host = os.environ.get("SMTP_HOST")
        if not host and not dry_run:
            raise ValueError("SMTP_HOST not configured")
        sender = os.environ.get("SMTP_FROM", "forge@localhost")
        recipient = os.environ.get("SMTP_TO", "operator@localhost")
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = sender
        message["To"] = recipient
        message["Message-ID"] = f"<{digest}@forge.local>"
        message.set_content(body)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(bytes(message))
        tmp.replace(path)
        if dry_run:
            return path

        host = os.environ["SMTP_HOST"]
        port = int(os.environ.get("SMTP_PORT", "465"))
        username = os.environ.get("SMTP_USERNAME")
        password = os.environ.get("SMTP_PASSWORD")
        mode = os.environ.get("SMTP_SECURITY", "ssl").lower()
        context = ssl.create_default_context()
        if mode == "ssl":
            with smtplib.SMTP_SSL(host, port, context=context, timeout=30) as smtp:
                if username:
                    smtp.login(username, password or "")
                smtp.send_message(message)
        elif mode == "starttls":
            with smtplib.SMTP(host, port, timeout=30) as smtp:
                smtp.starttls(context=context)
                if username:
                    smtp.login(username, password or "")
                smtp.send_message(message)
        else:
            raise ValueError("SMTP_SECURITY must be 'ssl' or 'starttls'")
        return path
