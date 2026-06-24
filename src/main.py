#!/usr/bin/env python3
import sys
import argparse
import logging
from dotenv import load_dotenv

# Asegurar que los imports relativos funcionen si se ejecuta desde la raíz
from src.core.scope_validator import ScopeValidator

# Configuración estética y profesional de logs
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("GhostBear-Hunter")

BANNER = """
====================================================================
  ____ _               _   ____                  _   _             _             
 / ___| |__   ___  ___| |_| __ )  ___  __ _ _ __| | | |_   _ _ __ | |_ ___ _ __  
| |   | '_ \ / _ \/ __| __|  _ \ / _ \/ _` | '__| |_| | | | | '_ \| __/ _ \ '__| 
| |___| | | | (_) \__ \ |_| |_) |  __/ (_| | |  |  _  | |_| | | | | ||  __/ |    
 \____|_| |_|\___/|___/\__|____/ \___|\__,_|_|  |_| |_|\__,_|_| |_|\__\___|_|    
                                                                                 
    [+] Framework de Automatización y Orquestación de Reconocimiento
    [+] Estado: Desarrollo - Core Activo
====================================================================
"""

def parse_arguments():
    """Define y procesa los argumentos de línea de comandos."""
    parser = argparse.ArgumentParser(
        description="GhostBear-Hunter: Orquestador inteligente de reconocimiento para Red Team y Bug Bounty."
    )
    
    # Target inputs
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-d", "--domain", help="Dominio objetivo individual para iniciar el escaneo (ej: target.com).")
    target_group.add_argument("--all-scope", action="store_true", help="Procesar todos los dominios base listados en config/scope.txt.")

    # Parámetros HTTPX (Flexibilidad para wrappers de Go)
    httpx_group = parser.add_argument_group("Configuración de HTTPX (Live Checker)")
    httpx_group.add_argument("-t", "--threads", type=int, default=50, help="Número de hilos concurrentes para httpx (Defecto: 50).")
    httpx_group.add_argument("--timeout", type=int, default=10, help="Timeout en segundos para las peticiones HTTP (Defecto: 10).")
    httpx_group.add_argument("--status-codes", type=str, default="200,301,302,403", help="Códigos de estado HTTP permitidos separados por comas (Defecto: 200,301,302,403).")

    # Modos de ejecución
    parser.add_argument("--silent", action="store_true", help="Modo silencioso: reduce el output visual de las herramientas subyacentes.")
    
    return parser.parse_args()

def main():
    print(BANNER)
    load_dotenv() # Carga variables desde el archivo .env si existen
    args = parse_arguments()

    try:
        # 1. Inicializar el Guardián de Scope
        logger.info("Inicializando el motor de validación de Scope...")
        validator = ScopeValidator()

        # 2. Determinar objetivos iniciales
        targets_to_process = []
        if args.domain:
            if validator.is_allowed(args.domain):
                targets_to_process.append(args.domain)
                logger.info(f"Objetivo directo validado exitosamente: {args.domain}")
            else:
                logger.error(f"El objetivo proporcionado '{args.domain}' está FUERA de alcance según las reglas vigentes.")
                sys.exit(1)
        elif args.all_scope:
            # Extraer los dominios limpios que se encuentren en el archivo de scope
            # Para usarlos como semillas en los módulos de recolección
            with open(validator.scope_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and not line.startswith("*."):
                        targets_to_process.append(line)
            logger.info(f"Cargadas {len(targets_to_process)} semillas desde el archivo de Scope.")

        if not targets_to_process:
            logger.error("No se encontraron objetivos válidos para procesar. Abortando.")
            sys.exit(1)

        # 3. Pipeline de Orquestación (Estructura de Stubs para el futuro)
        for target in targets_to_process:
            logger.info(f"Iniciando ciclo de reconocimiento para: {target}")
            
            # --- FASE 1: Enumeración de Subdominios ---
            # TODO: sub_recon.run(target)
            logger.info("[STUB] Ejecutando módulo de Sub-Recon...")
            discovered_subs = [target, f"api.{target}", f"staging.{target}", "out-of-scope-test.com"] 

            # Filtrado estricto post-recolección inmediata
            clean_subs = [sub for sub in discovered_subs if validator.is_allowed(sub)]
            logger.info(f"Subdominios filtrados por Scope: {len(clean_subs)} permitidos de {len(discovered_subs)} hallados.")

            # --- FASE 2: Extracción de URLs (Pasiva y Activa) ---
            # TODO: archive_crawler.run(clean_subs) (GAU)
            # TODO: spider_crawler.run(clean_subs)  (Katana)
            logger.info("[STUB] Ejecutando Crawlers (GAU / Katana)...")
            discovered_urls = [f"https://{clean_subs[0]}/login?id=1", f"https://{clean_subs[1]}/v1/secrets"]

            # --- FASE 3: Validación de Hosts Vivos ---
            # Aquí pasaremos dinámicamente los argumentos recibidos (threads, timeout, status-codes)
            # TODO: live_checker.run(discovered_urls, threads=args.threads, timeout=args.timeout, codes=args.status_codes)
            logger.info(f"[STUB] Verificando endpoints vivos con HTTPX [Hilos: {args.threads} | Timeout: {args.timeout}s]")

            # --- FASE 4: Análisis Estático de Patrones ---
            # TODO: pattern_analyzer.run()
            logger.info("[STUB] Buscando patrones sensibles y fugas de información...")

            # --- FASE 5: Triaje Cognitivo con IA ---
            # TODO: ai_mentor.generate_blueprint()
            logger.info("[STUB] Generando Exploitation Blueprint con Gemini-2.5-Flash...")

        logger.info("Pipeline de GhostBear-Hunter finalizado con éxito.")

    except KeyboardInterrupt:
        logger.warning("\n[!] Operación cancelada por el usuario. Saliendo de forma limpia...")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Error inesperado en el flujo principal del orquestador: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
