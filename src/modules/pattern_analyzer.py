import logging
import re
from urllib.parse import urlparse, parse_qs
from typing import List, Dict, Any

logger = logging.getLogger("GhostBear-Hunter.PatternAnalyzer")

class PatternAnalyzer:
    """Analizador estático encargado de categorizar parámetros de riesgo y detectar secretos expuestos en URLs."""

    def __init__(self):
        # Firmas de parámetros calientes según vectores de ataque comunes
        self.risk_signatures = {
            "rce_lfi": re.compile(r"^(file|page|doc|root|path|include|dir|cmd|exec|command|run|shell)$", re.IGNORECASE),
            "ssrf_redirect": re.compile(r"^(url|redirect|dest|destination|target|link|to|path|continue|domain|host|file_path|uri)$", re.IGNORECASE),
            "sqli_id": re.compile(r"^(id|select|report|query|search|num|code|user|category|post|update)$", re.IGNORECASE)
        }
        
        # Detección básica de tokens / llaves expuestas en texto plano en la cadena de parámetros
        self.secret_signatures = re.compile(r"(key|token|auth|secret|password|passwd|api_key|apikey|jwt|bearer)", re.IGNORECASE)

    def run(self, live_urls: List[str]) -> Dict[str, Any]:
        """
        Mastica el pool de URLs activas y las segrega por criticidad o potencial vector
        para facilitar el triaje cognitivo.
        """
        logger.info(f"Iniciando análisis estático sobre {len(live_urls)} endpoints en busca de anomalías...")
        
        results: Dict[str, Any] = {
            "rce_lfi_targets": [],
            "ssrf_redirect_targets": [],
            "sqli_id_targets": [],
            "exposed_secrets_in_url": []
        }

        for url in live_urls:
            try:
                parsed_url = urlparse(url)
                parameters = parse_qs(parsed_url.query)
                
                if not parameters:
                    continue

                for param_name in parameters.keys():
                    # 1. Escaneo en busca de secretos en la URL
                    if self.secret_signatures.search(param_name):
                        logger.warning(f"Posible credencial/token expuesto en URL: {url}")
                        results["exposed_secrets_in_url"].append({"url": url, "param": param_name})

                    # 2. Categorización de vectores de ataque lógicos
                    if self.risk_signatures["rce_lfi"].match(param_name):
                        results["rce_lfi_targets"].append(url)
                    elif self.risk_signatures["ssrf_redirect"].match(param_name):
                        results["ssrf_redirect_targets"].append(url)
                    elif self.risk_signatures["sqli_id"].match(param_name):
                        results["sqli_id_targets"].append(url)

            except Exception as e:
                logger.debug(f"No se pudo parsear la estructura de la URL {url}: {e}")

        # Limpiar duplicados de listas por si una URL mapea a múltiples firmas
        for key in results.keys():
            if isinstance(results[key], list) and results[key] and isinstance(results[key][0], str):
                results[key] = list(set(results[key]))

        logger.info(f"Análisis completado. Hallazgos: "
                    f"LFI/RCE: {len(results['rce_lfi_targets'])} | "
                    f"SSRF/Redirect: {len(results['ssrf_redirect_targets'])} | "
                    f"SQLi Check: {len(results['sqli_id_targets'])} | "
                    f"Secretos en URL: {len(results['exposed_secrets_in_url'])}")
        
        return results
