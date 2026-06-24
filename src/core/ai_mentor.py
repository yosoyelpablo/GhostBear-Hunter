import os
import logging
from typing import List, Dict, Any
import google.generativeai as genai
from google.generativeai.types import GenerationConfig
from google import genai

logger = logging.getLogger("GhostBear-Hunter.AiMentor")

class AiMentor:
    """Cerebro táctico del framework. Consume la API de Gemini para procesar hallazgos y guiar el triaje de seguridad."""

    def __init__(self):
        # Extrae la API Key cargada desde el archivo .env central
        self.api_key = os.environ.get("GEMINI_API_KEY")
        if not self.api_key:
            logger.error("La variable de entorno 'GEMINI_API_KEY' no está configurada. "
                         "El módulo de IA funcionará en modo Simulación (Stub).")
            self.available = False
        else:
            genai.configure(api_key=self.api_key)
            # Usamos el modelo optimizado de alta velocidad y gran ventana de contexto
            self.model_name = "gemini-2.5-flash"
            self.available = True

    def generate_blueprint(self, target: str, subdomains: List[str], live_urls: List[str], analysis: Dict[str, Any]) -> str:
        """
        Analiza el compendio completo del reconocimiento y construye un informe estratégico 
        de vectores de entrada priorizados y recomendaciones de mitigación.
        """
        if not self.available:
            return "--- EXPLORATION BLUEPRINT (SIMULACIÓN) ---\nConfigurá GEMINI_API_KEY para habilitar el análisis cognitivo real."

        logger.info(f"Iniciando consulta al mentor táctico con {self.model_name}...")

        # 1. Definición formal del Rol del Sistema (Separado del prompt de datos)
        system_role = (
            "Sos un Asesor Senior de Seguridad Ofensiva y Mentor de Red Team. Tu objetivo es procesar "
            "datos crudos de reconocimiento de infraestructura obtenidos por nuestro orquestador automático y "
            "generar un 'Exploitation Blueprint' quirúrgico, claro y directo. Hablás de forma puramente técnica, "
            "omitís introducciones genéricas, saludos o advertencias redundantes. Hablás de un profesional Senior a otro."
        )

        # 2. Formateo limpio de las muestras de datos para el contexto de la IA
        def format_sample(items: List[Any]) -> str:
            if not items:
                return "Ninguno detectado."
            # Si son diccionarios (como en los secretos), extraemos una vista limpia
            if isinstance(items[0], dict):
                return "\n".join(f" - URL: {i.get('url')} | Parámetro: {i.get('param')}" for i in items[:5])
            return "\n".join(f" - {item}" for item in items[:5])

        # 3. Construcción del Prompt de ejecución (Datos + Estructura)
        prompt = f"""
        Procesá el siguiente compendio de reconocimiento táctico y estructurá el reporte de prioridades.

        OBJETIVO: {target}
        
        --- MÉTRICAS GENERALES ---
        - Subdominios In-Scope Detectados: {len(subdomains)}
        - Endpoints Vivos Confirmados (HTTPX): {len(live_urls)}
        
        --- RESUMEN DE VECTORES DETECTADOS ---
        * Potenciales LFI / RCE (Parámetros de archivos/comandos): {len(analysis.get('rce_lfi_targets', []))}
        * Potenciales SSRF / Open Redirect (Parámetros de redirección): {len(analysis.get('ssrf_redirect_targets', []))}
        * Parámetros de Tipo ID (Posibles SQLi / IDORs): {len(analysis.get('sqli_id_targets', []))}
        * Alertas de Posibles Secretos / Tokens en URL: {len(analysis.get('exposed_secrets_in_url', []))}

        --- MUESTRA DE ENTRADAS DE ALTA PRIORIDAD (MÁX. 5 POR CATEGORÍA) ---
        
        [Subdominios Activos]
        {format_sample(subdomains)}

        [Sospecha de LFI / RCE]
        {format_sample(analysis.get('rce_lfi_targets', []))}

        [Sospecha de SSRF / Redirect]
        {format_sample(analysis.get('ssrf_redirect_targets', []))}

        [Sospecha de SQLi / IDOR]
        {format_sample(analysis.get('sqli_id_targets', []))}

        [Alertas de Secretos Expuestos]
        {format_sample(analysis.get('exposed_secrets_in_url', []))}

        --- REQUISITOS DE LA RESPUESTA ---
        Escribí el reporte estructurado exactamente con las siguientes secciones:
        1. **Resumen de Superficie de Ataque**: Diagnóstico rápido y ejecutivo de la infraestructura expuesta.
        2. **Vectores de Ataque Priorizados**: Qué endpoints o subdominios específicos de la muestra representan el mayor riesgo y deben verificarse manualmente primero (justificación técnica).
        3. **Guía de Verificación Manual Rápida**: Proveé payloads conceptuales estándar no destructivos de ejemplo (ej: usando '../', 'http://169.254.169.254' o lógicas de comillas) adaptados exactamente a los nombres de los parámetros provistos en la muestra para validar falsos positivos.
        """

        try:
            # Configuración para estabilizar la respuesta técnica (Baja temperatura = Menos alucinación)
            config = GenerationConfig(
                temperature=0.2,
                max_output_tokens=2048
            )

            # Inicializamos el modelo inyectando las instrucciones del sistema nativas
            model = genai.GenerativeModel(
                model_name=self.model_name,
                system_instruction=system_role
            )
            
            # Realizamos la llamada pasando el prompt y la configuración
            response = model.generate_content(prompt, generation_config=config)
            return response.text

        except Exception as e:
            logger.error(f"Error crítico al conectar con el servicio de Gemini: {e}")
            return f"Error en la generación del Blueprint por IA: {e}"
