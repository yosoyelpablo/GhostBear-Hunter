import shutil
import subprocess
import logging
from typing import Set, List

logger = logging.getLogger("GhostBear-Hunter.LiveChecker")

class LiveChecker:
    """Wrapper de alto rendimiento para HTTPX, encargado de la validación activa de endpoints."""

    def __init__(self):
        self.binary_name = "httpx"
        self._check_dependency()

    def _check_dependency(self) -> None:
        """Verifica la existencia de httpx en el entorno del sistema."""
        if not shutil.which(self.binary_name):
            logger.error(f"El binario '{self.binary_name}' no se encuentra en el PATH. "
                         "Instalalo usando: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
            self.available = False
        else:
            self.available = True

    def run(self, urls: Set[str], threads: int, timeout: int, status_codes: str) -> List[str]:
        """
        Envía el pool de URLs recolectadas a HTTPX vía stdin para comprobar cuáles están vivas
        y responden bajo los criterios de filtrado seleccionados.
        """
        if not self.available:
            logger.warning("Saltando validación de hosts vivos debido a la falta de 'httpx'. Devolviendo pool sin filtrar.")
            return list(urls)

        if not urls:
            logger.info("No hay URLs cargadas en el pool para verificar con HTTPX.")
            return []

        live_endpoints: List[str] = []
        logger.info(f"Filtrando {len(urls)} URLs con HTTPX [Hilos: {threads} | Timeout: {timeout}s | Códigos: {status_codes}]...")

        # Configuración dinámica del binario sin interactuar con la Shell
        cmd = [
            self.binary_name,
            "-t", str(threads),
            "-timeout", str(timeout),
            "-mc", status_codes,
            "-silent",
            "-no-color"
        ]

        try:
            # Unimos el set de URLs por saltos de línea para pasarlas limpias al buffer stdin
            stdin_data = "\n".join(urls)
            logger.debug(f"Lanzando proceso: {' '.join(cmd)}")
            
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            # Inyección directa por pipeline de memoria y recolección de respuestas masivas
            stdout_output, stderr_output = process.communicate(input=stdin_data)

            if process.returncode != 0 and stderr_output:
                if "error" in stderr_output.lower():
                    logger.warning(f"HTTPX emitió una alerta durante el escaneo: {stderr_output.strip()}")

            # Parseo inmediato línea por línea de los objetivos vivos devueltos
            for line in stdout_output.splitlines():
                endpoint = line.strip()
                if endpoint:
                    live_endpoints.append(endpoint)

        except Exception as e:
            logger.error(f"Error crítico durante la orquestación de HTTPX: {e}")

        logger.info(f"Filtrado completado. Endpoints activos que responden al criterio: {len(live_endpoints)}")
        return live_endpoints
