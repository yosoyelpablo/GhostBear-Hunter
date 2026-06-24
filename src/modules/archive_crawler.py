import shutil
import subprocess
import logging
from typing import List, Set
from src.core.scope_validator import ScopeValidator

logger = logging.getLogger("GhostBear-Hunter.ArchiveCrawler")

class ArchiveCrawler:
    """Wrapper optimizado para GAU (GetAllUrls) enfocado en la extracción de endpoints históricos."""
    
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
        Recibe la lista de subdominios activos y ejecuta GAU mediante stdin.
        Busca únicamente los directorios, archivos y parámetros de esos hosts exactos (sin buscar subdominios).
        """
        if not self.available:
            logger.warning("Saltando Archive Crawler debido a la falta del binario 'gau'.")
            return set()

        if not domains:
            logger.warning("No se proporcionaron dominios para procesar en Archive Crawler.")
            return set()

        discovered_urls: Set[str] = set()
        logger.info(f"Iniciando recolección de directorios históricos con GAU para {len(domains)} hosts...")

        # Ejecutamos GAU sin el flag '--subs' y sin pasarle un dominio directo como argumento.
        # Al dejarlo vacío, el binario queda esperando la lista completa de objetivos por stdin.
        cmd = [self.binary_name]
        
        try:
            logger.debug(f"Lanzando proceso unificado de GAU: {' '.join(cmd)}")
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,   # Habilitamos la entrada para inyectar la lista
                stdout=subprocess.PIPE,  # Capturamos la salida de URLs
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1                # Modo streaming línea por línea
            )

            # Convertimos la lista de dominios en un solo string separado por saltos de línea
            input_data = "\n".join(domains) + "\n"
            
            # Inyectamos los objetivos al stdin y cerramos el flujo de entrada para que comience a trabajar
            if process.stdin:
                process.stdin.write(input_data)
                process.stdin.close()

            # Procesamos la salida de URLs en tiempo real a medida que van apareciendo
            if process.stdout:
                for line in process.stdout:
                    url = line.strip()
                    if url:
                        # Control de protección legal inmediato
                        if self.validator.is_allowed(url):
                            discovered_urls.add(url)
                        else:
                            logger.debug(f"URL filtrada por Scope (Out-of-Scope): {url}")

            # Esperar el cierre limpio del proceso y verificar errores severos
            _, stderr_output = process.communicate()
            if process.returncode != 0 and stderr_output:
                if "error" in stderr_output.lower():
                    logger.warning(f"GAU reportó una incidencia durante la recolección: {stderr_output.strip()}")

        except Exception as e:
            logger.error(f"Error crítico en la ejecución unificada de GAU: {e}")

        logger.info(f"GAU finalizado. Endpoints únicos e In-Scope hallados: {len(discovered_urls)}")
        return discovered_urls
