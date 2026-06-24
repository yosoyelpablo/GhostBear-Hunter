import os
import logging
from typing import List, Dict, Any
import google.generativeai as genai

logger = logging.getLogger("GhostBear-Hunter.AiMentor")

class AiMentor:
    """Cerebro táctico del framework. Consume la API de Gemini para procesar hallazgos y guiar al Red Team."""

    def __init__(self):
        # Extrae la API Key cargada desde el archivo .env central
        self.api_key = os.environ.get("GEMINI_API_KEY")
        if not self.api_key:
            logger.error("La variable de entorno 'GEMINI_API_KEY' no está configurada. "
                         "El módulo de IA funcionará en modo Simulación (Stub).")
            self.available = False
        else:
            genai.configure(api_key=self.api_key)
            # Usamos el modelo optimizado y veloz de la suite de Gemini
            self.model_name = "gemini-2.5-flash"
            self.available = True

    def generate_blueprint(self, target: str, subdomains: List[str], live_urls: List[str], analysis: Dict[str, Any]) -> str:
        """
        Analiza el compendio completo del reconocimiento y construye un informe estratégico 
        de vectores de entrada priorizados.
        """
        logger.info(f"Iniciando consulta al mentor táctico con {self.model_name}...")

        # Construcción del contexto enriquecido de ciberseguridad ofensiva
        prompt = f"""
        Sos un Asesor Senior de Seguridad Ofensiva y Mentor de Red Team. Tu objetivo es procesar los datos de reconocimiento de infraestructura crudos obtenidos por nuestro orquestador automático y generar un "Exploitation Blueprint" quirúrgico, claro y directo.

        OBJETIVO: {target}
        
        --- METRICS ---
        - Subdominios In-Scope Detectados: {len(subdomains)}
        - Endpoints Vivos (HTTPX): {len(live_urls)}
        
        --- VECTORES DE RIESGO DETECTADOS ---
        * Potenciales LFI / RCE (Parámetros calientes): {len(analysis.get('rce_lfi_targets', []))}
        * Potenciales SSRF / Open Redirect (Parámetros de redirección): {len(analysis.get('ssrf_redirect_targets', []))}
        * Parámetros de Tipo ID (Posibles SQLi / IDORs): {len(analysis.get('sqli_id_targets', []))}
        * Posibles Secretos / Tokens en URL: {len(analysis.get('exposed_secrets_in_url', []))}

        --- MUESTRA DE DATOS DE ALTA PRIORIDAD ---
        Subdominios (Primeros 5): {subdomains[:5]}
        Endpoints con sospecha de LFI: {analysis.get('rce_lfi_targets', [])[:5]}
        Endpoints con sospecha de SSRF: {analysis.get('ssrf_redirect_targets', [])[:5]}
        Endpoints con sospecha de SQLi: {analysis.get('sqli_id_targets', [])[:5]}
        Alertas de Secretos: {analysis.get('exposed_secrets_in_url', [])[:5]}

        --- INSTRUCCIONES DE RESPUESTA ---
        Escribí un reporte puramente técnico y conciso estructurado de la siguiente forma:
        1. **Resumen de Superficie de Ataque**: Diagnóstico rápido de la infraestructura expuesta.
        2. **Vectores de Ataque Priorizados**: Qué endpoints o subdominios deberíamos atacar manualmente primero y por qué (justificación de riesgo).
        3. **Guía de Explotación Manual Rápida**: Proveé payloads de ejemplo específicos (conceptos de pruebas lógicas no destructivas como `../`, `http://169.254.169.254`, `' OR 1=1--`) adaptados a los parámetros de la muestra para verificar si hay vulnerabilidades reales.
        
        Sé directo, omití introducciones genéricas o advertencias redundantes. Hablá como un Hacker Senior a otro.
        """

        if not self.available:
            return "--- EXPLORATION BLUEPRINT (SIMULACIÓN) ---\nConfigurá GEMINI_API_KEY para habilitar el análisis cognitivo real."

        try:
            model = genai.GenerativeModel(self.model_name)
            response = model.generate_content(prompt)
            return response.text
        except Exception as e:
            logger.error(f"Error crítico al conectar con el servicio de Gemini: {e}")
            return f"Error en la generación del Blueprint por IA: {e}"
