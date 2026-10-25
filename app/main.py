
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Depends
from app.safety_engine import threat_detector
from sqlalchemy import (
    Boolean,
    DateTime,
    Integer,
    String,
    Text,
    create_engine,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session
from pydantic import BaseModel, Field
from typing import Literal
from uuid import uuid4

DATABASE_URL = "sqlite:///./shield.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(bind=engine)
def get_db():
    with SessionLocal() as session:
        yield session


class Base(DeclarativeBase):
    pass


class SecurityEventRecord(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    asset_id: Mapped[str] = mapped_column(String(100))
    source: Mapped[str] = mapped_column(String(100))
    event_type: Mapped[str] = mapped_column(String(100))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20))
    simulated: Mapped[bool] = mapped_column(Boolean, default=True)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )


class SecurityEvent(BaseModel):
    asset_id: str = Field(min_length=1, max_length=100)
    source: str = Field(min_length=1, max_length=100)
    event_type: str = Field(min_length=1, max_length=100)
    description: str = Field(min_length=1, max_length=1000)
    severity: Literal["low", "medium", "high", "critical"]
    simulated: bool = True


def serialize_event(event: SecurityEventRecord):
    return {
        "id": event.event_id,
        "asset_id": event.asset_id,
        "source": event.source,
        "event_type": event.event_type,
        "description": event.description,
        "severity": event.severity,
        "simulated": event.simulated,
        "received_at": event.received_at.isoformat(),
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="AI Mobile Shield Enterprise",
    version="0.2.0",
    description="Security monitoring backend development",
    lifespan=lifespan,
)


@app.get("/")
def home():
    return {
        "project": "AI Mobile Shield Enterprise",
        "status": "running",
        "database": "SQLite",
    }



@app.get("/health")
def health(session: Session = Depends(get_db)):
    session.execute(select(1))

    return {
        "status": "healthy",
        "database": "connected",
        "security_coverage": "not_configured",
    }



@app.post("/api/v1/events", status_code=201)
def create_event(
    event: SecurityEvent,
    session: Session = Depends(get_db),
):
    event_data = event.model_dump()
    detection = None

    if event.event_type.lower() in {
        "failed_login",
        "failed_login_test",
        "login_failed",
    }:
        detection = threat_detector.record_failed_login(
            asset_id=event.asset_id,
            source_ip=event.source,
        )

    record = SecurityEventRecord(
        event_id=str(uuid4()),
        **event_data,
    )
    session.add(record)

    if detection and detection["detected"]:
        alert_record = SecurityEventRecord(
            event_id=str(uuid4()),
            asset_id=event.asset_id,
            source=event.source,
            event_type="repeated_failed_login",
            description=(
                f"Repeated failed logins detected: "
                f"{detection['attempts']} attempts within "
                f"{detection['window_minutes']} minutes."
            ),
            severity="high",
            simulated=True,
        )
        session.add(alert_record)

    session.commit()
    session.refresh(record)

    return {
        "message": "Security event saved",
        "event": serialize_event(record),
        "threat_detection": detection,
    }



@app.get("/api/v1/events")
def list_events(session: Session = Depends(get_db)):
    events = session.scalars(
        select(SecurityEventRecord).order_by(
            SecurityEventRecord.id.desc()
        )
    ).all()

    return {
        "count": len(events),
        "events": [serialize_event(event) for event in events],
    }

from fastapi.responses import FileResponse
from pathlib import Path

@app.get("/dashboard", include_in_schema=False)
def dashboard():
    return FileResponse(
        Path(__file__).with_name("dashboard.html")
    )
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)