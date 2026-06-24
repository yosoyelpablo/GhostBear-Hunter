#!/usr/bin/env python3
import os
import sys
import argparse
import logging
from datetime import datetime
from dotenv import load_dotenv

# Componentes del Core y Módulos del Pipeline Activos
from src.core.scope_validator import ScopeValidator
from src.modules.sub_recon import SubRecon
from src.modules.archive_crawler import ArchiveCrawler
from src.modules.spider_crawler import SpiderCrawler
from src.modules.live_checker import LiveChecker
from src.modules.pattern_analyzer import PatternAnalyzer
from src.core.ai_mentor import AiMentor

# Configuración estética de logs
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("GhostBear-Hunter")

BANNER = r"""
====================================================================
  ____ _                  _   ____                 _   _             _             
 / ___| |__   ___  ___| |_|  _ \  ___  __ _ _ __| | | |_  _ _ __ | |_ ___ _ __  
| |    | '_ \ / _ \/ __| __| |_) / _ \/ _` | '__| |_| | | | | '_ \| __/ _ \ '__| 
| |___| | | | (_) \__ \ |_|  _ <  __/ (_| | |  |  _  | |_| | | | | ||  __/ |    
 \____|_| |_|\___/|___/\__|_| \_\___|\__,_|_|  |_| |_|\__,_|_| |_|\__\___|_|    
                                                                                
    [+] Framework de Automatización y Orquestación de Reconocimiento
    [+] Estado: Desarrollo - Pipeline Core 100% Sincronizado (Fix)
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

    # Parámetros Operativos Globales (Evasión y Rendimiento)
    op_group = parser.add_argument_group("Configuración de Rendimiento y Políticas de Red")
    op_group.add_argument("-t", "--threads", type=int, default=40, help="Número de hilos concurrentes para los subprocesos (Defecto: 40).")
    op_group.add_argument("-rl", "--rate-limit", type=int, default=15, help="Límite estricto de peticiones por segundo (RPS) por herramienta (Defecto: 15).")
    op_group.add_argument("--timeout", type=int, default=10, help="Timeout en segundos para las peticiones HTTP (Defecto: 10).")
    op_group.add_argument("--status-codes", type=str, default="200,301,302,403", help="Códigos de estado HTTP permitidos (Defecto: 200,301,302,403).")
    op_group.add_argument("--user-agent", type=str, default="GhostBear-Hunter-Scanner/1.0", help="User-Agent personalizado para las cabeceras HTTP.")
    op_group.add_argument("--header", type=str, default="", help="Cabecera custom opcional en formato 'Nombre: Valor' (ej: 'X-BugBounty: pablo').")

    parser.add_argument("--silent", action="store_true", help="Modo silencioso.")
    
    return parser.parse_args()

def save_report(target: str, content: str) -> str:
    """Guarda de forma segura el blueprint generado por la IA en la carpeta outputs/."""
    try:
        os.makedirs("outputs", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"outputs/{target}_blueprint_{timestamp}.md"
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
        return filename
    except Exception as e:
        logger.error(f"No se pudo guardar el reporte en disco: {e}")
        return ""

def main():
    print(BANNER)
    load_dotenv()  
    args = parse_arguments()

    try:
        # 1. Inicializar el Guardián de Scope
        logger.info("Inicializando el motor de validación de Scope...")
        validator = ScopeValidator()

        # 2. Inicializar Módulos del Pipeline
        sub_recon = SubRecon(validator)
        archive_crawler = ArchiveCrawler(validator)
        spider_crawler = SpiderCrawler(validator)
        live_checker = LiveChecker()
        pattern_analyzer = PatternAnalyzer()
        ai_mentor = AiMentor()

        # 3. Determinar objetivos iniciales (Semillas)
        targets_to_process = []
        if args.domain:
            if validator.is_allowed(args.domain):
                targets_to_process.append(args.domain)
                logger.info(f"Objetivo directo validado exitosamente: {args.domain}")
            else:
                logger.error(f"El objetivo proporcionado '{args.domain}' está FUERA de alcance según las reglas.")
                sys.exit(1)
        elif args.all_scope:
            with open(validator.scope_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and not line.startswith("*."):
                        targets_to_process.append(line)
            logger.info(f"Cargadas {len(targets_to_process)} semillas desde el archivo de Scope.")

        if not targets_to_process:
            logger.error("No se encontraron objetivos válidos para procesar. Abortando.")
            sys.exit(1)

        # 4. Pipeline de Orquestación Secuencial Sincronizado
        for target in targets_to_process:
            logger.info(f"================================================================")
            logger.info(f"INICIANDO PIPELINE OPERATIVO PARA: {target}")
            logger.info(f"================================================================")
            
            # --- FASE 1: Enumeración de Subdominios (Pasiva) ---
            discovered_subs = sub_recon.run(target, rate_limit=args.rate_limit, threads=args.threads)
            
            # CORRECCION: Si no hay subs, usamos el propio dominio como semilla
            clean_subs = list(discovered_subs) if discovered_subs else [target]
            
            # --- FASE 2: Extracción de URLs Históricas y Activas ---
            gau_urls = archive_crawler.run(clean_subs)
            katana_urls = spider_crawler.run(
                subdomains=clean_subs, 
                depth=2, 
                rate_limit=args.rate_limit, 
                custom_header=args.header, 
                user_agent=args.user_agent
            )
            
            all_discovered_urls = gau_urls.union(katana_urls)
            logger.info(f"Consolidado total de URLs In-Scope para {target}: {len(all_discovered_urls)} objetivos únicos.")

            # --- FASE 3: Validación de Hosts Vivos (HTTPX) ---
            live_urls = live_checker.run(
                urls=all_discovered_urls,
                threads=args.threads,
                timeout=args.timeout,
                status_codes=args.status_codes,
                rate_limit=args.rate_limit,
                custom_header=args.header,
                user_agent=args.user_agent
            )

            if not live_urls:
                logger.warning(f"No se detectaron endpoints vivos respondiendo para {target}.")
                continue

            # --- FASE 4: Análisis Estático de Patrones y Parámetros Hot ---
            analysis_results = pattern_analyzer.run(live_urls)

            # --- FASE 5: Triaje Cognitivo con IA y Reporte ---
            logger.info("Enviando resultados consolidados al motor de IA (Gemini)...")
            blueprint = ai_mentor.generate_blueprint(target, analysis_results)
            
            if blueprint:
                report_path = save_report(target, blueprint)
                if report_path:
                    logger.info(f"[+] ¡Operación Exitosa! Blueprint estratégico consolidado en: {report_path}")
            else:
                logger.error("El motor de IA no pudo estructurar la hipótesis de ataque.")

    except KeyboardInterrupt:
        logger.warning("\n[!] Operación global abortada por el usuario via KeyboardInterrupt. Saliendo de forma segura...")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Falla crítica catastrófica en el bucle principal: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
