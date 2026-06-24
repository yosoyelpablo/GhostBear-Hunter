import shutil
import subprocess
import logging
from typing import List, Set
from src.core.scope_validator import ScopeValidator

logger = logging.getLogger("GhostBear-Hunter.ArchiveCrawler")

class ArchiveCrawler:
    """Wrapper robusto para la herramienta GAU (GetAllUrls)."""
    
    def __init__(self, validator: ScopeValidator):
        self.validator = validator
        self.binary_name = "gau"
        self._check_dependency()

    def _check_dependency(self) -> None:
        """Verifica si el binario de GAU está instalado en el PATH del sistema."""
        if not shutil.which(self.binary_name):
            logger.error(f"El binario '{self.binary_name}' no se encuentra en el PATH. "
                         "Por favor, instalalo con: go install github.com/lc/gau/v2/cmd/gau@latest")
            self.available = False
        else:
            self.available = True

    def run(self, domains: List[str]) -> Set[str]:
        """
        Ejecuta GAU para una lista de dominios y filtra los resultados
        en tiempo real asegurando el cumplimiento del alcance.
        """
        if not self.available:
            logger.warning("Saltando Archive Crawler debido a la falta del binario 'gau'.")
            return set()

        discovered_urls: Set[str] = set()
        logger.info(f"Iniciando recolección histórica con GAU para {len(domains)} dominios...")

        for domain in domains:
            # Construcción segura del comando sin shell=True
            cmd = [self.binary_name, "--subs", domain]
            
            try:
                logger.debug(f"Ejecutando comando: {' '.join(cmd)}")
                
                # Usamos Popen para procesar el output línea por línea (streaming) sin saturar la RAM
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1
                )

                # Procesar salida en tiempo real
                if process.stdout:
                    for line in process.stdout:
                        url = line.strip()
                        if url:
                            # Filtro de protección legal inmediato
                            if self.validator.is_allowed(url):
                                discovered_urls.add(url)
                            else:
                                logger.debug(f"URL filtrada por Scope (Out-of-Scope): {url}")

                # Esperar a que termine y capturar posibles errores de ejecución
                _, stderr_output = process.communicate()
                if process.returncode != 0 and stderr_output:
                    logger.warning(f"GAU reportó una alerta para {domain}: {stderr_output.strip()}")

            except Exception as e:
                logger.error(f"Error crítico ejecutando GAU en el dominio {domain}: {e}")

        logger.info(f"GAU finalizado. Endpoints válidos e In-Scope hallados: {len(discovered_urls)}")
        return discovered_urls
