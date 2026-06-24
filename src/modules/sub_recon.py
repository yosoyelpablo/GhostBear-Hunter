import subprocess
import shutil
import logging
from typing import Set
from src.core.scope_validator import ScopeValidator

logger = logging.getLogger("GhostBear-Hunter.SubRecon")

class SubRecon:
    def __init__(self, validator: ScopeValidator):
        """Inicializa el módulo de enumeración pasiva verificando el entorno."""
        self.validator = validator
        self.binary_name = "subfinder"
        self.available = shutil.which(self.binary_name) is not None
        
        if not self.available:
            logger.error(f"Falta una dependencia crítica: '{self.binary_name}' no está en el PATH.")

    def run(self, target: str, rate_limit: int, threads: int) -> Set[str]:
        """
        Ejecuta subfinder en modo streaming, validando el alcance en tiempo real
        y controlando de forma segura los recursos del sistema.
        """
        if not self.available:
            logger.warning("SubRecon omitido: binario subfinder no disponible.")
            return set()

        if not target:
            logger.error("SubRecon recibió un target vacío. Abortando fase.")
            return set()

        logger.info(f"Iniciando enumeración pasiva con Subfinder para: {target}")
        subdomains: Set[str] = set()

        # Construcción dinámica del comando basado en el settings.json
        cmd = [
            self.binary_name,
            "-d", target,
            "-t", str(threads),
            "-rl", str(rate_limit),
            "-silent",
            "-no-color"
        ]

        process = None
        try:
            # Redirigimos stderr a DEVNULL o STDOUT para evitar que el buffer se llene y congele el script
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.DEVNULL, 
                text=True
            )
            
            # Streaming en tiempo real del output de subfinder
            for line in process.stdout:
                sub = line.strip()
                if not sub:
                    continue
                    
                # Filtro estricto usando el Guardián Legal (ScopeValidator)
                if self.validator.is_allowed(sub):
                    subdomains.add(sub)
                    logger.debug(f"[In-Scope] Subdominio detectado: {sub}")
                else:
                    logger.debug(f"[Out-of-Scope] Subdominio ignorado: {sub}")
            
            # Esperamos que el proceso termine y capturamos el código de estado
            return_code = process.wait()
            
            if return_code == 0:
                logger.info(f"Subfinder finalizó exitosamente. {len(subdomains)} subdominios consolidados In-Scope.")
            else:
                logger.error(f"Subfinder terminó con un código de error no esperado: {return_code}")
            
        except KeyboardInterrupt:
            logger.warning("\n[!] Interrupción detectada en SubRecon. Terminando subprocesos de Go...")
            if process:
                process.kill()  # Matamos el binario para no dejar zombies
                process.wait()
            raise  # Propagamos la interrupción al main.py para una salida limpia global
            
        except Exception as e:
            logger.error(f"Error crítico inesperado en el wrapper de Subfinder: {e}", exc_info=True)
            if process:
                process.kill()
                process.wait()

        return subdomains
