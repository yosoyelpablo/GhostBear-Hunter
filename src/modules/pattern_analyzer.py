import logging
import re
from urllib.parse import urlparse, parse_qs
from typing import List, Dict, Any

logger = logging.getLogger("GhostBear-Hunter.PatternAnalyzer")

class PatternAnalyzer:
    """Analizador estático encargado de categorizar parámetros de riesgo y detectar secretos expuestos en URLs."""

    def __init__(self):
        # Firmas ampliadas de parámetros calientes según vectores de ataque comunes (Bug Bounty / Pentesting)
        self.risk_signatures = {
            "rce_lfi": re.compile(
                r"^(file|page|doc|root|path|include|dir|cmd|exec|command|run|shell|source|template|cat|inc|load)$", 
                re.IGNORECASE
            ),
            "ssrf_redirect": re.compile(
                r"^(url|redirect|dest|destination|target|link|to|path|continue|domain|host|file_path|uri|callback|checkout|checkout_url|feed|window|view)$", 
                re.IGNORECASE
            ),
            "sqli_id": re.compile(
                r"^(id|select|report|query|search|num|code|user|category|post|update|sort|order|filter|limit|offset)$", 
                re.IGNORECASE
            )
        }
        
        # Detección de tokens, llaves o credenciales expuestas en la cadena de parámetros (Query String)
        self.secret_signatures = re.compile(
            r"(key|token|auth|secret|password|passwd|api_key|apikey|jwt|bearer|cred|private)", 
            re.IGNORECASE
        )

    def run(self, live_urls: List[str]) -> Dict[str, Any]:
        """
        Analiza el pool de URLs activas y las segrega por potencial vector de ataque 
        utilizando sets nativos para garantizar la unicidad de los endpoints de forma eficiente.
        """
        logger.info(f"Iniciando análisis estático sobre {len(live_urls)} endpoints en busca de anomalías y parámetros hot...")
        
        # Inicializamos los targets de riesgo como sets para evitar duplicados nativamente en memoria
        analysis_pool: Dict[str, Any] = {
            "rce_lfi_targets": set(),
            "ssrf_redirect_targets": set(),
            "sqli_id_targets": set(),
            "exposed_secrets_in_url": []  # Mantiene lista para estructurar los dicts de hallazgos
        }

        # Set auxiliar para evitar guardar exactamente el mismo secreto duplicado en la misma URL
        seen_secrets = set()

        for url in live_urls:
            try:
                parsed_url = urlparse(url)
                parameters = parse_qs(parsed_url.query)
                
                if not parameters:
                    continue

                for param_name in parameters.keys():
                    # 1. Escaneo de secretos expuestos en la Query String
                    if self.secret_signatures.search(param_name):
                        secret_identifier = f"{url}||{param_name}"
                        if secret_identifier not in seen_secrets:
                            seen_secrets.add(secret_identifier)
                            logger.warning(f"Posible credencial/token expuesto en URL: {url} -> Parámetro: {param_name}")
                            analysis_pool["exposed_secrets_in_url"].append({
                                "url": url, 
                                "param": param_name
                            })

                    # 2. Categorización de vectores de ataque lógicos (Estructura limpia sin elifs cruzados)
                    if self.risk_signatures["rce_lfi"].match(param_name):
                        analysis_pool["rce_lfi_targets"].add(url)
                        
                    if self.risk_signatures["ssrf_redirect"].match(param_name):
                        analysis_pool["ssrf_redirect_targets"].add(url)
                        
                    if self.risk_signatures["sqli_id"].match(param_name):
                        analysis_pool["sqli_id_targets"].add(url)

            except Exception as e:
                logger.debug(f"No se pudo parsear la estructura de la URL {url}: {e}")

        # Convertimos los sets internos a listas antes de retornar para mantener la compatibilidad del pipeline
        results = {
            "rce_lfi_targets": list(analysis_pool["rce_lfi_targets"]),
            "ssrf_redirect_targets": list(analysis_pool["ssrf_redirect_targets"]),
            "sqli_id_targets": list(analysis_pool["sqli_id_targets"]),
            "exposed_secrets_in_url": analysis_pool["exposed_secrets_in_url"]
        }

        logger.info(f"Análisis estático completado de forma exitosa. Resumen de hallazgos:\n"
                    f" └─ LFI/RCE Pseudos: {len(results['rce_lfi_targets'])}\n"
                    f" └─ SSRF/Redirect Pseudos: {len(results['ssrf_redirect_targets'])}\n"
                    f" └─ SQLi Check Pseudos: {len(results['sqli_id_targets'])}\n"
                    f" └─ Secretos expuestos hallados: {len(results['exposed_secrets_in_url'])}")
        
        return results
