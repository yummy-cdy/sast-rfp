from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base

class User(Base):
    __tablename__ = "users"
    user_id = Column(String(50), primary_key=True, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="USER")
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

class Project(Base):
    __tablename__ = "projects"
    project_id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    source_type = Column(String(50), nullable=False)
    target_language = Column(String(50), nullable=False)
    source_path = Column(String(255), nullable=False)
    created_by = Column(String(50), ForeignKey("users.user_id"))
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

class ProjectPermission(Base):
    __tablename__ = "project_permissions"
    project_id = Column(
        Integer, ForeignKey("projects.project_id", ondelete="CASCADE"), primary_key=True
    )
    user_id = Column(
        String(50), ForeignKey("users.user_id", ondelete="CASCADE"), primary_key=True
    )

class DiagnosticCriteria(Base):
    __tablename__ = "diagnostic_criteria"
    criteria_id = Column(String(50), primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=False)
    standard_id = Column(String(50), nullable=False)
    category = Column(String(100), nullable=False)
    item_number = Column(String(50), nullable=False)
    reference_info = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    default_severity = Column(String(20), nullable=False)
    # SFR-013: 진단 항목별 구현 상태 (IMPLEMENTED | PLANNED)
    implementation_status = Column(String(20), nullable=False, default="PLANNED")

class AnalysisExecution(Base):
    __tablename__ = "analysis_executions"
    execution_id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.project_id"))
    engine_type = Column(String(50), nullable=False)
    target_language = Column(String(50), nullable=False)
    status = Column(String(20), nullable=False, default="WAIT")
    executed_by = Column(String(50), ForeignKey("users.user_id"))
    start_time = Column(DateTime, nullable=True)
    end_time = Column(DateTime, nullable=True)
    error_info = Column(Text, nullable=True)
    summary = Column(JSON, nullable=True)

class DiagnosticResult(Base):
    __tablename__ = "diagnostic_results"
    result_id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    execution_id = Column(Integer, ForeignKey("analysis_executions.execution_id"))
    criteria_id = Column(String(50), nullable=False)
    criteria_name = Column(String(100), nullable=False)
    standard_id = Column(String(50), nullable=False)
    target_language = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    confidence = Column(String(20), nullable=False)
    file_path = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    evidence = Column(Text, nullable=False)
    recommendation = Column(Text, nullable=True)
    raw_result = Column(JSON, nullable=True)