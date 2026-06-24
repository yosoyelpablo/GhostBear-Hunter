import subprocess
import shutil
import logging
from typing import List, Set
from src.core.scope_validator import ScopeValidator

logger = logging.getLogger("GhostBear-Hunter.SpiderCrawler")

class SpiderCrawler:
    def __init__(self, validator: ScopeValidator):
        """Inicializa el crawler activo verificando que Katana esté disponible."""
        self.validator = validator
        self.binary_name = "katana"
        self.available = shutil.which(self.binary_name) is not None

        if not self.available:
            logger.error(f"Falta una dependencia crítica: '{self.binary_name}' no está en el PATH.")

    def run(self, subdomains: List[str], depth: int, rate_limit: int, custom_header: str, user_agent: str) -> Set[str]:
        """
        Ejecuta Katana a través de inyección por stdin en modo streaming.
        Soporta cancelación limpia y previene bloqueos de buffer.
        """
        if not self.available:
            logger.warning("SpiderCrawler omitido: binario katana no disponible.")
            return set()

        if not subdomains:
            logger.warning("SpiderCrawler no recibió subdominios para rastrear.")
            return set()

        logger.info(f"Iniciando Spidering activo con Katana (Profundidad: {depth} | Rate Limit: {rate_limit} RPS)...")
        discovered_urls: Set[str] = set()

        # Construcción exacta del comando según la política del JSON
        cmd = [
            self.binary_name,
            "-d", str(depth),
            "-rl", str(rate_limit),
            "-silent",
            "-no-color"
        ]

        # Inyección de cabeceras de identidad exigidas por las plataformas
        if user_agent:
            cmd.extend(["-H", f"User-Agent: {user_agent}"])
        if custom_header and ":" in custom_header:
            cmd.extend(["-H", custom_header])

        process = None
        try:
            # Enviamos stderr a DEVNULL para evitar colgar el buffer de salida de errores
            process = subprocess.Popen(
                cmd, 
                stdin=subprocess.PIPE, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.DEVNULL, 
                text=True
            )
            
            # Inyectamos los subdominios en el stdin de Katana
            input_data = "\n".join(subdomains) + "\n"
            try:
                process.stdin.write(input_data)
                process.stdin.close()
            except BrokenPipeError:
                logger.error("Katana cerró la conexión inesperadamente al recibir los datos (Broken Pipe).")

            # Streaming de URLs descubiertas en tiempo real
            for line in process.stdout:
                url = line.strip()
                if not url:
                    continue
                
                # Filtro de alcance perimetral
                if self.validator.is_allowed(url):
                    discovered_urls.add(url)
                    logger.debug(f"[Crawler-URL] {url}")

            return_code = process.wait()
            if return_code == 0:
                logger.info(f"Katana finalizó exitosamente. Extraídas {len(discovered_urls)} URLs válidas.")
            else:
                logger.error(f"Katana terminó con código de error: {return_code}")

        except KeyboardInterrupt:
            logger.warning("\n[!] Interrupción detectada en SpiderCrawler. Matando procesos de Katana...")
            if process:
                process.kill()
                process.wait()
            raise
            
        except Exception as e:
            logger.error(f"Error inesperado en el wrapper de Katana: {e}", exc_info=True)
            if process:
                process.kill()
                process.wait()

        return discovered_urls
