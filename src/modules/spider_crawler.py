import shutil
import subprocess
import logging
from typing import List, Set
from src.core.scope_validator import ScopeValidator

logger = logging.getLogger("GhostBear-Hunter.SpiderCrawler")

class SpiderCrawler:
    """Wrapper optimizado de alto rendimiento para el crawler web dinámico Katana."""

    def __init__(self, validator: ScopeValidator):
        self.validator = validator
        self.binary_name = "katana"
        self._check_dependency()

    def _check_dependency(self) -> None:
        """Verifica si el binario de Katana está instalado en el PATH del sistema."""
        if not shutil.which(self.binary_name):
            logger.error(f"El binario '{self.binary_name}' no se encuentra en el PATH. "
                         "Instalalo con: go install github.com/projectdiscovery/katana/cmd/katana@latest")
            self.available = False
        else:
            self.available = True

    def run(self, targets: List[str], depth: int = 3) -> Set[str]:
        """
        Lanza Katana de forma masiva usando stdin para procesar múltiples objetivos en paralelo,
        parseando endpoints y aplicando validación estricta de alcance en tiempo real.
        """
        if not self.available:
            logger.warning("Saltando Spider Crawler debido a la falta del binario 'katana'.")
            return set()

        if not targets:
            logger.warning("No se proporcionaron objetivos para procesar en Spider Crawler.")
            return set()

        discovered_urls: Set[str] = set()
        logger.info(f"Iniciando crawling activo paralelo con Katana para {len(targets)} hosts (Profundidad: {depth})...")

        # Configuración de optimización masiva para automatización.
        # Al no declarar el flag '-u', Katana entiende de forma nativa que debe leer del stdin.
        cmd = [
            self.binary_name,
            "-d", str(depth),
            "-jc",              # Parsea archivos JavaScript y busca endpoints ocultos
            "-silent",          # Evita banners e información innecesaria en stdout
            "-no-color"         # Salida limpia para procesar strings sin caracteres ANSI
        ]

        try:
            logger.debug(f"Lanzando proceso unificado de Katana: {' '.join(cmd)}")
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,   # Habilitamos la entrada para inyectar los objetivos
                stdout=subprocess.PIPE,  # Capturamos el streaming de URLs descubiertas
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1                # Modo streaming línea por línea
            )

            # Normalizamos y unificamos la lista de objetivos agregando el esquema si falta
            input_data = "\n".join(t if "://" in t else f"http://{t}" for t in targets) + "\n"
            
            # Inyectamos la masa de datos al proceso y cerramos el canal de entrada
            if process.stdin:
                process.stdin.write(input_data)
                process.stdin.close()

            # Procesamos la salida de URLs concurrentes en tiempo real a medida que el motor de Katana las escupe
            if process.stdout:
                for line in process.stdout:
                    url = line.strip()
                    if url:
                        # Filtro de protección legal inmediato sobre la marcha
                        if self.validator.is_allowed(url):
                            discovered_urls.add(url)
                        else:
                            logger.debug(f"Katana halló un enlace Out-of-Scope descartado: {url}")

            # Esperar el cierre limpio del proceso y atrapar errores severos
            _, stderr_output = process.communicate()
            if process.returncode != 0 and stderr_output:
                if "error" in stderr_output.lower():
                    logger.warning(f"Katana reportó una incidencia durante el crawling activo: {stderr_output.strip()}")

        except Exception as e:
            logger.error(f"Error crítico en la ejecución masiva de Katana: {e}")

        logger.info(f"Katana finalizado. Endpoints únicos e In-Scope hallados: {len(discovered_urls)}")
        return discovered_urls
