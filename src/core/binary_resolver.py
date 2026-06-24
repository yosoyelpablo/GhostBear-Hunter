import os
import subprocess
import logging

logger = logging.getLogger("GhostBear-Hunter.BinaryResolver")


def _find_all_candidates(name: str):
    """Recorre cada directorio del PATH y devuelve TODAS las rutas ejecutables
    que coincidan con 'name', sin quedarse solo con la primera (a diferencia
    de shutil.which, que para en el primer match)."""
    candidates = []
    seen = set()
    path_dirs = os.environ.get("PATH", "").split(os.pathsep)

    for directory in path_dirs:
        if not directory:
            continue
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            real = os.path.realpath(candidate)
            if real not in seen:
                seen.add(real)
                candidates.append(candidate)
    return candidates


def resolve_binary(name: str, signature: str, version_flag: str = "-h") -> str:
    """
    Resuelve la ruta absoluta correcta de un binario cuando existe ambigüedad
    de nombres en el sistema (ej: 'httpx' de ProjectDiscovery en Go vs.
    'httpx' de la librería de Python con el mismo nombre de comando).

    Args:
        name: nombre del binario a buscar (ej: 'httpx').
        signature: substring que debe aparecer en la salida de --help/-version
                   del binario correcto (ej: 'projectdiscovery').
        version_flag: flag a usar para obtener la salida identificable.

    Returns:
        Ruta absoluta del binario correcto, o cadena vacía si no se encontró
        ningún candidato que coincida con la firma esperada.
    """
    candidates = _find_all_candidates(name)

    if not candidates:
        logger.debug(f"No se encontró ningún binario llamado '{name}' en el PATH.")
        return ""

    for candidate in candidates:
        try:
            result = subprocess.run(
                [candidate, version_flag],
                capture_output=True,
                text=True,
                timeout=5
            )
            output = (result.stdout + result.stderr).lower()
            if signature.lower() in output:
                logger.debug(f"Binario '{name}' resuelto correctamente en: {candidate}")
                return candidate
        except Exception as e:
            logger.debug(f"No se pudo verificar el candidato '{candidate}' para '{name}': {e}")
            continue

    logger.warning(
        f"Se hallaron {len(candidates)} binario(s) llamados '{name}' en el PATH, "
        f"pero ninguno coincide con la firma esperada. Candidatos revisados: {candidates}"
    )
    return ""
