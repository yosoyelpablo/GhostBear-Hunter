import shutil
import subprocess
import logging
from typing import Set, List
from src.core.scope_validator import ScopeValidator

logger = logging.getLogger("GhostBear-Hunter.SubRecon")

class SubRecon:
    """Wrapper de alto rendimiento para Subfinder, encargado de la enumeración pasiva de subdominios."""

    def __init__(self, validator: ScopeValidator):
        self.validator = validator
        self.binary_name = "subfinder"
        self._check_dependency()

    def _check_dependency(self) -> None:
        """Verifica si el binario de subfinder está instalado en el PATH del sistema."""
        if not shutil.which(self.binary_name):
            logger.error(f"El binario '{self.binary_name}' no se encuentra en el PATH. "
                         "Instalalo usando: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
            self.available = False
        else:
            self.available = True

    def run(self, domain: str) -> Set[str]:
        """
        Ejecuta subfinder para un dominio objetivo y filtra los subdominios
        descubiertos en tiempo real aplicando control de Scope estricto.
        """
        if not self.available:
            logger.warning(f"Saltando Fase 1 para {domain} debido a la falta del binario 'subfinder'.")
            return {domain}

        discovered_subs: Set[str] = set()
        logger.info(f"Iniciando enumeración pasiva de subdominios para: {domain}")

        # Configuración optimizada de Subfinder para automatización
        cmd = [
            self.binary_name,
            "-d", domain,
            "-silent",          # Elimina banners de texto decorativos
            "-no-color"         # Salida limpia en texto plano
        ]

        try:
            logger.debug(f"Lanzando proceso: {' '.join(cmd)}")
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            # Procesamiento iterativo en tiempo real por cada línea del stdout
            if process.stdout:
                for line in process.stdout:
                    subdomain = line.strip()
                    if subdomain:
                        # Validación inmediata de alcance
                        if self.validator.is_allowed(subdomain):
                            discovered_subs.add(subdomain)
                        else:
                            logger.debug(f"Subdominio descartado por reglas de Scope (Out-of-Scope): {subdomain}")

            _, stderr_output = process.communicate()
            if process.returncode != 0 and stderr_output:
                if "error" in stderr_output.lower():
                    logger.warning(f"Subfinder reportó un problema para {domain}: {stderr_output.strip()}")

        except Exception as e:
            logger.error(f"Error crítico ejecutando Subfinder en el objetivo {domain}: {e}")

        # Aseguramos que al menos el dominio base esté presente si pasó el filtro
        if self.validator.is_allowed(domain):
            discovered_subs.add(domain)

        logger.info(f"Fase 1 completada para {domain}. Subdominios válidos e In-Scope hallados: {len(discovered_subs)}")
        return discovered_subs
