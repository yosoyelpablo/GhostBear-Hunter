import os
import re
import logging
from typing import List, Set
from urllib.parse import urlparse

logger = logging.getLogger("GhostBear-Hunter.Core")

class ScopeValidator:
    """
    Gestiona y valida de forma estricta si un objetivo (URL o Dominio)
    se encuentra dentro del alcance (In-Scope) y fuera de la lista negra (Out-of-Scope).
    """
    def __init__(self, scope_path: str = "config/scope.txt", blacklist_path: str = "config/blacklist.txt"):
        self.scope_path = scope_path
        self.blacklist_path = blacklist_path
        self.in_scope_patterns: List[re.Pattern] = []
        self.blacklist_patterns: List[re.Pattern] = []
        self._load_all_scopes()

    def _compile_pattern(self, line: str) -> re.Pattern:
        """
        Convierte una línea de texto con comodines comunes (ej. *.domain.com)
        o un dominio plano en una Expresión Regular estricta.
        """
        cleaned = line.strip().lower()
        # Si ya es una regex compleja definida por el usuario, la dejamos pasar
        if cleaned.startswith("^") or cleaned.endswith("$"):
            return re.compile(cleaned)
        
        # Convertir comodín clásico *.domain.com a regex válida
        if cleaned.startswith("*."):
            base_domain = re.escape(cleaned[2:])
            # Machea domain.com o cualquier subdominio.domain.com
            return re.compile(rf"^(.*\.)?{base_domain}$")
        
        # Dominio exacto o IP plana
        return re.compile(rf"^{re.escape(cleaned)}$")

    def _load_file_patterns(self, path: str) -> List[re.Pattern]:
        """Lee un archivo de configuración, limpia comentarios y compila las reglas."""
        patterns = []
        if not os.path.exists(path):
            logger.warning(f"Archivo de configuración no encontrado: {path}. Se asumirá vacío.")
            return patterns

        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        compiled = self._compile_pattern(line)
                        patterns.append(compiled)
                    except re.error as e:
                        logger.error(f"Error al compilar regla de scope '{line}' en {path}: {e}")
        except Exception as e:
            logger.critical(f"Error fatal leyendo el archivo {path}: {e}")
        
        return patterns

    def _load_all_scopes(self) -> None:
        """Inicializa los listados de control de acceso."""
        self.in_scope_patterns = self._load_file_patterns(self.scope_path)
        self.blacklist_patterns = self._load_file_patterns(self.blacklist_path)
        logger.info(f"Filtros cargados -> In-Scope: {len(self.in_scope_patterns)} | Blacklist: {len(self.blacklist_patterns)}")

    def _normalize_target(self, target: str) -> str:
        """Extrae el host/dominio purificado eliminando esquemas, puertos o rutas."""
        target = target.strip().lower()
        if "://" in target:
            parsed = urlparse(target)
            host = parsed.hostname or ""
        else:
            # Si no tiene esquema, asegurar que urlparse no rompa el host si viene con rutas
            parsed = urlparse(f"http://{target}")
            host = parsed.hostname or ""
        
        # Remover puertos si existen (ej: target.com:8443)
        if ":" in host:
            host = host.split(":")[0]
            
        return host

    def is_allowed(self, target: str) -> bool:
        """
        Determina con precisión quirúrgica si un elemento debe ser procesado.
        Regla de oro: Debe emparejar con In-Scope Y NUNCA emparejar con Blacklist.
        """
        if not target:
            return False

        domain = self._normalize_target(target)
        if not domain:
            return False

        # 1. Verificar si está explícitamente prohibido (Blacklist toma precedencia absoluta)
        for pattern in self.blacklist_patterns:
            if pattern.match(domain):
                logger.debug(f"Acceso Denegado: '{domain}' coincide con la Blacklist.")
                return False

        # 2. Verificar si está autorizado (In-Scope)
        for pattern in self.in_scope_patterns:
            if pattern.match(domain):
                return True

        logger.debug(f"Acceso Denegado: '{domain}' está fuera del alcance permitido.")
        return False
