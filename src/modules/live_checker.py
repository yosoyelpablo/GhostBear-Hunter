import subprocess
import shutil
import logging
from typing import Set, List

logger = logging.getLogger("GhostBear-Hunter.LiveChecker")

class LiveChecker:
    def __init__(self):
        """Inicializa el validador de hosts vivos comprobando HTTPX."""
        self.binary_name = "httpx"
        self.available = shutil.which(self.binary_name) is not None

        if not self.available:
            logger.error(f"Falta una dependencia crítica: '{self.binary_name}' no está en el PATH.")

    def run(self, urls: Set[str], threads: int, timeout: int, status_codes: str, rate_limit: int, custom_header: str, user_agent: str) -> List[str]:
        """
        Valida de forma sutil qué URLs están vivas y responden a los códigos de estado configurados.
        Maneja entrada masiva mediante streaming seguro de stdin.
        """
        if not self.available:
            logger.warning("LiveChecker omitido: binario httpx no disponible.")
            return []

        if not urls:
            logger.warning("LiveChecker no recibió URLs para validar.")
            return []

        logger.info(f"Verificando hosts vivos con HTTPX a {rate_limit} RPS (Hilos globales: {threads})...")
        live_endpoints: List[str] = []

        # Estructura del comando dinámico blindado
        cmd = [
            self.binary_name,
            "-t", str(threads),
            "-timeout", str(timeout),
            "-mc", status_codes,
            "-rl", str(rate_limit),  # <-- Aplicación del Rate Limit sutil
            "-silent",
            "-no-color"
        ]

        if user_agent:
            cmd.extend(["-H", f"User-Agent: {user_agent}"])
        if custom_header and ":" in custom_header:
            cmd.extend(["-H", custom_header])

        process = None
        try:
            process = subprocess.Popen(
                cmd, 
                stdin=subprocess.PIPE, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.DEVNULL, 
                text=True
            )
            
            # Mandamos el lote de endpoints descubiertos por el caño
            input_data = "\n".join(urls) + "\n"
            try:
                process.stdin.write(input_data)
                process.stdin.close()
            except BrokenPipeError:
                logger.error("HTTPX cerró el pipe de entrada abruptamente.")

            # Captura de hosts vivos en tiempo real
            for line in process.stdout:
                endpoint = line.strip()
                if endpoint:
                    live_endpoints.append(endpoint)
                    logger.info(f"[ALIVE] {endpoint}")

            return_code = process.wait()
            if return_code != 0:
                logger.error(f"HTTPX finalizó con un código de salida anómalo: {return_code}")
            else:
                logger.info(f"Validación HTTPX completada. {len(live_endpoints)} endpoints en línea.")

        except KeyboardInterrupt:
            logger.warning("\n[!] Interrupción detectada en LiveChecker. Terminando binarios de HTTPX...")
            if process:
                process.kill()
                process.wait()
            raise
            
        except Exception as e:
            logger.error(f"Error crítico en el wrapper de HTTPX: {e}", exc_info=True)
            if process:
                process.kill()
                process.wait()

        return live_endpoints
