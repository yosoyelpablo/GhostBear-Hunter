import shutil
import subprocess
import logging
from typing import List, Set
from src.core.scope_validator import ScopeValidator

logger = logging.getLogger("GhostBear-Hunter.SpiderCrawler")

class SpiderCrawler:
    """Wrapper optimizado para el crawler web dinámico Katana."""

    def __init__(self, validator: ScopeValidator):
        self.validator = validator
        self.binary_name = "katana"
        self._check_dependency()

    def _check_dependency(self) -> None:
        """Verifica si el binario de Katana está instalado en el PATH."""
        if not shutil.which(self.binary_name):
            logger.error(f"El binario '{self.binary_name}' no se encuentra en el PATH. "
                         "Instalalo con: go install github.com/projectdiscovery/katana/cmd/katana@latest")
            self.available = False
        else:
            self.available = True

    def run(self, targets: List[str], depth: int = 3) -> Set[str]:
        """
        Lanza Katana contra los objetivos provistos, parseando endpoints
        y aplicando validación estricta de alcance en cada acierto.
        """
        if not self.available:
            logger.warning("Saltando Spider Crawler debido a la falta del binario 'katana'.")
            return set()

        discovered_urls: Set[str] = set()
        logger.info(f"Iniciando crawling activo con Katana (Profundidad: {depth})...")

        for target in targets:
            # Asegurar formato de URL básica para que Katana no falle en el parseo inicial
            normalized_target = target if "://" in target else f"http://{target}"
            
            # Argumentos de optimización para Bug Bounty / Red Team
            cmd = [
                self.binary_name,
                "-u", normalized_target,
                "-d", str(depth),
                "-jc",              # Parsea archivos JavaScript y busca endpoints ocultos
                "-silent",          # Evita banners e información innecesaria en stdout
                "-no-color"         # Salida limpia para procesar strings sin caracteres ANSI
            ]

            try:
                logger.debug(f"Ejecutando comando: {' '.join(cmd)}")
                
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1
                )

                if process.stdout:
                    for line in process.stdout:
                        url = line.strip()
                        if url:
                            if self.validator.is_allowed(url):
                                discovered_urls.add(url)
                            else:
                                logger.debug(f"Katana halló un enlace Out-of-Scope descartado: {url}")

                _, stderr_output = process.communicate()
                if process.returncode != 0 and stderr_output:
                    # Katana suele mandar logs de info a stderr, solo alertamos si son errores graves
                    if "error" in stderr_output.lower():
                        logger.warning(f"Katana reportó un error para {target}: {stderr_output.strip()}")

            except Exception as e:
                logger.error(f"Error crítico ejecutando Katana en {target}: {e}")

        logger.info(f"Katana finalizado. Endpoints válidos e In-Scope hallados: {len(discovered_urls)}")
        return discovered_urls
