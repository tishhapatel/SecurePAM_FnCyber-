"""
Reusable pagination and sorting utilities for list endpoints.

List endpoints should use apply_sorting() with an explicit allowlist of
sortable columns, then paginate() to apply LIMIT/OFFSET and return a
PaginatedResponse.

Example:
    query = select(Asset).where(Asset.is_deleted == False)
    query = apply_sorting(
        query,
        Asset,
        pagination.sort_by,
        pagination.sort_order,
        allowed_columns={"name", "created_at", "criticality"},
    )
    return await paginate(db, query, pagination, schema=AssetOut)
"""

from typing import Any, Optional, Sequence, Type, TypeVar

from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select

from app.schemas.common import PaginatedResponse, PaginationParams

ModelT = TypeVar("ModelT")
SchemaT = TypeVar("SchemaT", bound=BaseModel)

MAX_PAGE_SIZE = 100


def apply_sorting(
    query: Select,
    model: Type[Any],
    sort_by: Optional[str],
    sort_order: str,
    allowed_columns: Sequence[str],
) -> Select:
    """
    Apply ORDER BY to `query`, restricted to `allowed_columns` — sort_by is
    client-controlled input, so it must never be used to build SQL for an
    arbitrary attribute (that would let a caller sort/leak by columns the
    endpoint never intended to expose, e.g. hashed_password).
    """
    if not sort_by or sort_by not in allowed_columns:
        return query

    column = getattr(model, sort_by)
    return query.order_by(column.desc() if sort_order == "desc" else column.asc())


async def paginate(
    db: AsyncSession,
    query: Select,
    pagination: PaginationParams,
    schema: Type[SchemaT],
) -> PaginatedResponse[SchemaT]:
    """Execute `query` with LIMIT/OFFSET applied and wrap the result + total count."""
    page = max(pagination.page, 1)
    page_size = min(max(pagination.page_size, 1), MAX_PAGE_SIZE)

    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()

    result = await db.execute(query.limit(page_size).offset((page - 1) * page_size))
    items = [schema.model_validate(row) for row in result.scalars().all()]

    pages = (total + page_size - 1) // page_size if total else 0

    return PaginatedResponse[schema](
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )
