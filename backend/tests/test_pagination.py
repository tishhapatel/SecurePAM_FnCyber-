"""
Pagination/sorting utilities (app/core/pagination.py) — no endpoint uses
these yet, so they're exercised directly against the seeded Asset rows.
"""

import uuid

import pytest
from pydantic import BaseModel, ConfigDict, ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.pagination import apply_sorting, paginate
from app.models.asset import Asset
from app.schemas.common import PaginationParams


class _AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    name: str
    criticality: str


async def test_paginate_returns_correct_total_and_page_size(db_session: AsyncSession):
    # Seed data creates exactly 5 assets.
    pagination = PaginationParams(page=1, page_size=2)
    query = select(Asset)
    result = await paginate(db_session, query, pagination, schema=_AssetOut)

    assert result.total == 5
    assert result.page_size == 2
    assert len(result.items) == 2
    assert result.pages == 3


async def test_paginate_second_page_returns_remaining_items(db_session: AsyncSession):
    pagination = PaginationParams(page=3, page_size=2)
    query = select(Asset)
    result = await paginate(db_session, query, pagination, schema=_AssetOut)

    assert result.total == 5
    assert len(result.items) == 1  # 5 items, page size 2 -> last page has 1


async def test_paginate_caps_page_size_at_maximum(db_session: AsyncSession):
    pagination = PaginationParams(page=1, page_size=10_000)
    query = select(Asset)
    result = await paginate(db_session, query, pagination, schema=_AssetOut)

    assert result.page_size == 100  # MAX_PAGE_SIZE
    assert result.total == 5


async def test_apply_sorting_rejects_unlisted_column(db_session: AsyncSession):
    """sort_by must be allowlisted — this is a security boundary, not just
    a UX nicety (prevents sorting/leaking by columns like hashed_password)."""
    query = select(Asset)
    sorted_query = apply_sorting(
        query, Asset, sort_by="ip_address", sort_order="asc", allowed_columns=["name"]
    )
    # ip_address isn't in allowed_columns, so no ORDER BY was added — the
    # query compiles to the same SQL as the unsorted one.
    assert str(sorted_query) == str(query)


async def test_apply_sorting_orders_by_allowed_column(db_session: AsyncSession):
    query = select(Asset)
    sorted_query = apply_sorting(
        query, Asset, sort_by="name", sort_order="asc", allowed_columns=["name"]
    )
    result = await db_session.execute(sorted_query)
    names = [row.name for row in result.scalars().all()]
    assert names == sorted(names)


def test_pagination_accepts_valid_sort_orders():
    assert PaginationParams(sort_order="asc").sort_order == "asc"
    assert PaginationParams(sort_order="desc").sort_order == "desc"


def test_pagination_rejects_invalid_sort_order():
    with pytest.raises(ValidationError):
        PaginationParams(sort_order="invalid")
