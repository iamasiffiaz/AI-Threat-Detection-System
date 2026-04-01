"""
Detection Rules router (SIEM-style).
GET    /rules               — list all rules
POST   /rules               — create rule
GET    /rules/{id}          — get rule
PUT    /rules/{id}          — update rule
DELETE /rules/{id}          — delete rule
POST   /rules/{id}/toggle   — enable / disable rule
POST   /rules/test          — test a rule against sample log
"""
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_admin, get_current_analyst
from app.models.rule import DetectionRule
from app.schemas.rule import RuleCreate, RuleResponse, RuleTestRequest, RuleTestResponse, RuleUpdate
from app.services.rule_engine import evaluate_single_condition

router = APIRouter(prefix="/rules", tags=["Detection Rules"])


@router.get("", response_model=List[RuleResponse])
async def list_rules(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_analyst),
):
    result = await db.execute(select(DetectionRule).order_by(DetectionRule.created_at.desc()))
    return result.scalars().all()


@router.post("", response_model=RuleResponse, status_code=201)
async def create_rule(
    payload: RuleCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_admin),
):
    """Create a new detection rule (admin only)."""
    existing = await db.execute(select(DetectionRule).where(DetectionRule.name == payload.name))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Rule with this name already exists")

    rule = DetectionRule(**payload.model_dump(), created_by=current_user.username)
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return rule


@router.get("/{rule_id}", response_model=RuleResponse)
async def get_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_analyst),
):
    rule = await _get_or_404(rule_id, db)
    return rule


@router.put("/{rule_id}", response_model=RuleResponse)
async def update_rule(
    rule_id: int,
    payload: RuleUpdate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_admin),
):
    """Update an existing detection rule (admin only)."""
    rule = await _get_or_404(rule_id, db)
    update_data = payload.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(rule, field, value)
    await db.commit()
    await db.refresh(rule)
    return rule


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_admin),
):
    """Delete a detection rule (admin only)."""
    rule = await _get_or_404(rule_id, db)
    await db.delete(rule)
    await db.commit()


@router.post("/{rule_id}/toggle", response_model=RuleResponse)
async def toggle_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_admin),
):
    """Enable or disable a rule."""
    rule = await _get_or_404(rule_id, db)
    rule.is_active = not rule.is_active
    await db.commit()
    await db.refresh(rule)
    return rule


@router.post("/test", response_model=RuleTestResponse)
async def test_rule(
    payload: RuleTestRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_analyst),
):
    """Test a rule against a sample log dict without ingesting it."""
    rule = await _get_or_404(payload.rule_id, db)
    matched = evaluate_single_condition(payload.log_sample, rule.conditions)
    return RuleTestResponse(
        matched=matched,
        rule_name=rule.name,
        details=f"Rule '{rule.name}' {'matched' if matched else 'did not match'} the sample log.",
    )


async def _get_or_404(rule_id: int, db: AsyncSession) -> DetectionRule:
    result = await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule
