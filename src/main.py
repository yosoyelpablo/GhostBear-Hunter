#!/usr/bin/env python3
import sys
import argparse
import logging
from dotenv import load_dotenv

# Componentes del Core y Módulos del Pipeline Activos
from src.core.scope_validator import ScopeValidator
from src.modules.sub_recon import SubRecon
from src.modules.archive_crawler import ArchiveCrawler
from src.modules.spider_crawler import SpiderCrawler
from src.modules.live_checker import LiveChecker
from src.core.ai_mentor import AiMentor

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
    [+] Estado: Desarrollo - Pipeline Core 100% Activo
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
    load_dotenv()  # Carga variables desde el archivo .env si existen
    args = parse_arguments()

    try:
        # 1. Inicializar el Guardián de Scope
        logger.info("Inicializando el motor de validación de Scope...")
        validator = ScopeValidator()

        # 2. Inicializar Wrappers del Pipeline (Inyección de dependencias jerárquica)
        sub_recon = SubRecon(validator)
        archive_crawler = ArchiveCrawler(validator)
        spider_crawler = SpiderCrawler(validator)
        live_checker = LiveChecker()

        # 3. Determinar objetivos iniciales (Semillas)
        targets_to_process = []
        if args.domain:
            if validator.is_allowed(args.domain):
                targets_to_process.append(args.domain)
                logger.info(f"Objetivo directo validado exitosamente: {args.domain}")
            else:
                logger.error(f"El objetivo proporcionado '{args.domain}' está FUERA de alcance según las reglas de scope.txt.")
                sys.exit(1)
        elif args.all_scope:
            # Extraer los dominios raíz limpios presentes en el archivo de alcance
            with open(validator.scope_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and not line.startswith("*."):
                        targets_to_process.append(line)
            logger.info(f"Cargadas {len(targets_to_process)} semillas desde el archivo de Scope.")

        if not targets_to_process:
            logger.error("No se encontraron objetivos válidos para procesar. Abortando.")
            sys.exit(1)

        # 4. Pipeline de Orquestación Secuencial
        for target in targets_to_process:
            logger.info(f"================================================================")
            logger.info(f"INICIANDO PIPELINE OPERATIVO PARA: {target}")
            logger.info(f"================================================================")
            
            # --- FASE 1: Enumeración de Subdominios (¡AHORA ACTIVA!) ---
            # Ejecución real de Subfinder cruzando datos contra el Scope en tiempo de ejecución
            clean_subs = list(sub_recon.run(target))
            
            if not clean_subs:
                logger.warning(f"No se detectaron subdominios permitidos para {target}. Saltando a la siguiente semilla.")
                continue

            # --- FASE 2: Extracción de URLs (Pasiva y Activa - ¡AHORA ACTIVA!) ---
            # GAU extrae endpoints históricos indexados en Wayback/CommonCrawl
            gau_urls = archive_crawler.run(clean_subs)
            
            # Katana realiza scraping activo y spidering sobre la estructura actual
            katana_urls = spider_crawler.run(clean_subs, depth=2)
            
            # Consolidación matemática libre de duplicados redundantes
            all_discovered_urls = gau_urls.union(katana_urls)
            logger.info(f"Consolidado total de URLs In-Scope para {target}: {len(all_discovered_urls)} objetivos únicos.")

            # --- FASE 3: Validación de Hosts Vivos (¡AHORA ACTIVA!) ---
            # HTTPX comprueba qué responde realmente eliminando falsos positivos caídos
            live_urls = live_checker.run(
                urls=all_discovered_urls,
                threads=args.threads,
                timeout=args.timeout,
                status_codes=args.status_codes
            )

            # --- FASE 4: Análisis Estático de Patrones ---
            # El input real del analizador ahora es el pool purificado y verificado de 'live_urls'
            # TODO: pattern_analyzer.run(live_urls)
            logger.info(f"[STUB] Buscando patrones sensibles en {len(live_urls)} endpoints validados en vivo...")

            # --- FASE 5: Triaje Cognitivo con IA ---
            # TODO: ai_mentor.generate_blueprint()
            logger.info("[STUB] Generando Exploitation Blueprint con Gemini-2.5-Flash...")

        logger.info("================================================================")
        logger.info("Pipeline de GhostBear-Hunter finalizado con éxito.")
        logger.info("================================================================")

    except KeyboardInterrupt:
        logger.warning("\n[!] Operación cancelada por el usuario. Saliendo de forma limpia...")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Error inesperado en el flujo principal del orquestador: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
