#!/usr/bin/env python3
import sys
import argparse
import logging
from dotenv import load_dotenv

# Componentes del Core y Módulos del Pipeline
from src.core.scope_validator import ScopeValidator
from src.modules.archive_crawler import ArchiveCrawler
from src.modules.spider_crawler import SpiderCrawler

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
    httpx_group.add_argument
