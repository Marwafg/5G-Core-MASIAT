from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.database import search_subscribers_secure, search_subscribers_vulnerable
from app.security import assert_safe_input, evaluate_payload, require_api_key

router = APIRouter(prefix="/api/udm", tags=["UDM"])


@router.get("/vulnerable/subscribers")
def vulnerable_subscriber_lookup(q: str = Query(min_length=1, max_length=120)) -> dict:
    rows = search_subscribers_vulnerable(q)
    return {
        "mode": "vulnerable",
        "query": q,
        "evaluation": evaluate_payload(q),
        "records_returned": len(rows),
        "records": rows,
    }


@router.get("/secure/subscribers", dependencies=[Depends(require_api_key)])
def secure_subscriber_lookup(q: str = Query(min_length=1, max_length=120)) -> dict:
    assert_safe_input(q)
    rows = search_subscribers_secure(q)
    return {
        "mode": "secure",
        "query": q,
        "evaluation": evaluate_payload(q),
        "records_returned": len(rows),
        "records": rows,
    }
