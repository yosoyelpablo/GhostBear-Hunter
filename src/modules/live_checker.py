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
            logger.warning("Saltando validación de hosts vivos debido a la falta de 'httpx'.")
            return list(urls) # Devolvemos el input original para no romper el pipeline, aunque sin filtrar

        if not urls:
            logger.info("No hay URLs cargadas en el pool para verificar con HTTPX.")
            return []

        live_endpoints: List[str] = []
        logger.info(f"Filtrando {len(urls)} URLs con HTTPX [Hilos: {threads} | Timeout: {args_timeout := timeout}s | Códigos: {status_codes}]...")

        # Construcción dinámica de flags de HTTPX
        cmd = [
            self.binary_name,
            "-t", str(threads),          # Hilos concurrentes
            "-timeout", str(timeout),    # Timeout de la petición
            "-mc", status_codes,         # Match Codes (ej: 200,301,302,403)
            "-silent",                   # Desactiva la barra de progreso y banners
            "-no-color"                  # Output crudo sin decoradores ANSI
        ]

        try:
            # Unimos las URLs con saltos de línea para inyectarlas por stdin
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

            # Comunicar envía los datos al stdin y cierra el stream, capturando la salida
            stdout_output, stderr_output = process.communicate(input=stdin_data)

            if process.returncode != 0 and stderr_output:
                if "error" in stderr_output.lower():
                    logger.warning(f"HTTPX emitió una alerta durante el escaneo: {stderr_output.strip()}")

            # Procesar la salida limpia (cada línea devuelta por HTTPX es una URL viva que macheó los códigos)
            for line in stdout_output.splitlines():
                endpoint = line.strip()
                if endpoint:
                    live_endpoints.append(endpoint)

        except Exception as e:
            logger.error(f"Error crítico durante la orquestación de HTTPX: {e}")

        logger.info(f"Filtrado completado. Endpoints activos que responden al criterio: {len(live_endpoints)}")
        return live_endpoints
