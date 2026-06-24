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
from src.modules.pattern_analyzer import PatternAnalyzer  # <-- Importación integrada
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
  ____ _                _   ____                  _   _             _             
 / ___| |__   ___  ___| |_| __ )   ___  __ _ _ __| | | |_   _ _ __ | |_ ___ _ __  
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
        spider_
