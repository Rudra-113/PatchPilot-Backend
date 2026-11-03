from fastapi import APIRouter, HTTPException

from app.services.scan_service import scan_repository
from app.services.ai_service import analyze_vulnerability
from app.services.patch_service import generate_patch
from app.services.patch_apply_service import apply_patch
from app.services.validation_service import validate_patch
from app.services.remediation_service import remediate_vulnerability
from app.services.rollback_service import rollback_patch
from app.services.cache_service import (
    get_analysis,
    save_analysis,
    get_patch,
    save_patch,
)


router = APIRouter(
    prefix="/scans",
    tags=["Scans"],
)


def _get_vulnerability(
    repository_id: str,
    vulnerability_id: str,
):
    result = scan_repository(repository_id)

    vulnerability = next(
        (
            item
            for item in result.get("vulnerabilities", [])
            if item.get("id") == vulnerability_id
        ),
        None,
    )

    if vulnerability is None:
        raise HTTPException(
            status_code=404,
            detail=f"Vulnerability {vulnerability_id} was not found.",
        )

    return vulnerability


def _get_analysis(
    repository_id: str,
    vulnerability: dict,
    repository_path: str,
):
    vulnerability_id = vulnerability["id"]

    cached = get_analysis(
        repository_id,
        vulnerability_id,
    )

    if cached is not None:
        return cached

    analysis = analyze_vulnerability(
        vulnerability,
        repository_path=repository_path,
    )

    save_analysis(
        repository_id,
        vulnerability_id,
        analysis,
    )

    return analysis


def _get_patch(
    repository_id: str,
    vulnerability: dict,
    analysis: dict,
    repository_path: str,
):
    vulnerability_id = vulnerability["id"]

    cached = get_patch(
        repository_id,
        vulnerability_id,
    )

    if cached is not None:
        return cached

    patch = generate_patch(
        vulnerability=vulnerability,
        analysis=analysis,
        repository_path=repository_path,
    )

    save_patch(
        repository_id,
        vulnerability_id,
        patch,
    )

    return patch


@router.post("/{repository_id}")
def create_scan(repository_id: str):
    try:
        result = scan_repository(repository_id)

        return {
            "repository_id": repository_id,
            "status": "completed",
            "results": result,
        }

    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


@router.post("/{repository_id}/analyze/{vulnerability_id}")
def analyze_scan_vulnerability(
    repository_id: str,
    vulnerability_id: str,
):
    try:
        vulnerability = _get_vulnerability(
            repository_id,
            vulnerability_id,
        )

        repository_path = f"scans/{repository_id}"

        analysis = _get_analysis(
            repository_id,
            vulnerability,
            repository_path,
        )

        return {
            "repository_id": repository_id,
            "vulnerability_id": vulnerability_id,
            "analysis": analysis,
            "cached": True,
        }

    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


@router.post("/{repository_id}/patch/{vulnerability_id}")
def generate_scan_patch(
    repository_id: str,
    vulnerability_id: str,
):
    try:
        vulnerability = _get_vulnerability(
            repository_id,
            vulnerability_id,
        )

        repository_path = f"scans/{repository_id}"

        analysis = _get_analysis(
            repository_id,
            vulnerability,
            repository_path,
        )

        patch = _get_patch(
            repository_id,
            vulnerability,
            analysis,
            repository_path,
        )

        return {
            "repository_id": repository_id,
            "vulnerability_id": vulnerability_id,
            "analysis": analysis,
            "patch": patch,
        }

    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


@router.post("/{repository_id}/apply-patch/{vulnerability_id}")
def apply_scan_patch(
    repository_id: str,
    vulnerability_id: str,
):
    try:
        vulnerability = _get_vulnerability(
            repository_id,
            vulnerability_id,
        )

        repository_path = f"scans/{repository_id}"

        analysis = _get_analysis(
            repository_id,
            vulnerability,
            repository_path,
        )

        patch = _get_patch(
            repository_id,
            vulnerability,
            analysis,
            repository_path,
        )

        applied = apply_patch(
            patch=patch,
            repository_path=repository_path,
        )

        return {
            "repository_id": repository_id,
            "vulnerability_id": vulnerability_id,
            "analysis": analysis,
            "patch": patch,
            "application": applied,
        }

    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


@router.post("/{repository_id}/validate-patch/{vulnerability_id}")
def validate_scan_patch(
    repository_id: str,
    vulnerability_id: str,
):
    try:
        vulnerability = _get_vulnerability(
            repository_id,
            vulnerability_id,
        )

        repository_path = f"scans/{repository_id}"

        analysis = _get_analysis(
            repository_id,
            vulnerability,
            repository_path,
        )

        patch = _get_patch(
            repository_id,
            vulnerability,
            analysis,
            repository_path,
        )

        validation = validate_patch(
            repository_id=repository_id,
            vulnerability=vulnerability,
            patch=patch,
            repository_path=repository_path,
        )

        return {
            "repository_id": repository_id,
            "vulnerability_id": vulnerability_id,
            "patch": patch,
            "validation": validation,
        }

    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


@router.post("/{repository_id}/remediate/{vulnerability_id}")
def remediate_scan_vulnerability(
    repository_id: str,
    vulnerability_id: str,
):
    try:
        return remediate_vulnerability(
            repository_id=repository_id,
            vulnerability_id=vulnerability_id,
        )

    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


@router.post("/{repository_id}/rollback/{vulnerability_id}")
def rollback_scan_patch(
    repository_id: str,
    vulnerability_id: str,
):
    try:
        vulnerability = _get_vulnerability(
            repository_id,
            vulnerability_id,
        )

        repository_path = f"scans/{repository_id}"

        analysis = _get_analysis(
            repository_id,
            vulnerability,
            repository_path,
        )

        patch = _get_patch(
            repository_id,
            vulnerability,
            analysis,
            repository_path,
        )

        applied = apply_patch(
            patch=patch,
            repository_path=repository_path,
        )

        rollback = rollback_patch(
            patch_result=applied,
            repository_path=repository_path,
        )

        return {
            "repository_id": repository_id,
            "vulnerability_id": vulnerability_id,
            "application": applied,
            "rollback": rollback,
        }

    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )