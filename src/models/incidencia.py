import os
import sys
from abc import ABC, abstractmethod

# Ajuste para ejecutar este módulo como script desde cualquier carpeta.
ruta_raiz = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if ruta_raiz not in sys.path:
    sys.path.insert(0, ruta_raiz)

from src.utils.excepciones import ValidacionException


class Incidencia(ABC):
    """Clase abstracta base para todas las incidencias de ciberseguridad.

    Atributos:
        id (str): Identificador único de la incidencia.
        titulo (str): Título descriptivo.
        descripcion (str): Descripción detallada.
        fecha (str): Fecha de la incidencia (formato YYYY-MM-DD).
        afectados (int): Número de afectados.
        riesgo (str): Nivel de riesgo calculado.
    """

    def __init__(self, id, titulo, descripcion, fecha, afectados):
        """Inicializa una incidencia con validación de datos."""
        self.validar_datos(id, titulo, descripcion, fecha, afectados)
        self.id = id
        self.titulo = titulo
        self.descripcion = descripcion
        self.fecha = fecha
        self.afectados = afectados
        self.riesgo = None

    def validar_datos(self, id, titulo, descripcion, fecha, afectados):
        """Valida los tipos y valores de los parámetros básicos."""
        if not isinstance(id, (str, int)) or not str(id).strip():
            raise ValidacionException("ID debe ser una cadena o entero no vacío")
        if not isinstance(titulo, str) or not titulo.strip():
            raise ValidacionException("Título debe ser una cadena no vacía")
        if not isinstance(descripcion, str) or not descripcion.strip():
            raise ValidacionException("Descripción debe ser una cadena no vacía")
        if not isinstance(fecha, str) or not fecha.strip():
            raise ValidacionException("Fecha debe ser una cadena no vacía")
        if not isinstance(afectados, int) or afectados < 0:
            raise ValidacionException("Afectados debe ser un entero no negativo")
        # Convertir ID a str si es int
        if isinstance(id, int):
            id = str(id)
        self.id = id

    @abstractmethod
    def calcular_riesgo(self):
        """Calcula y retorna el nivel de riesgo de la incidencia."""
        pass

    @abstractmethod
    def get_recomendaciones(self):
        """Retorna una lista de recomendaciones para mitigar la incidencia."""
        pass


class IncidenciaPhishing(Incidencia):
    """Incidencia de phishing: ataques que intentan robar credenciales mediante engaño.

    Atributos adicionales:
        url_maliciosa (str): URL del sitio falso.
        emails_afectados (int): Número de emails enviados o afectados.
    """

    def __init__(self, id, titulo, desc, fecha, afec, url_maliciosa, emails_afectados):
        """Inicializa una incidencia de phishing con validación específica."""
        super().__init__(id, titulo, desc, fecha, afec)
        self.validar_phishing(url_maliciosa, emails_afectados)
        self.url_maliciosa = url_maliciosa
        self.emails_afectados = emails_afectados

    def validar_phishing(self, url, emails):
        """Valida parámetros específicos de phishing."""
        if not isinstance(url, str):
            raise ValidacionException("URL maliciosa debe ser una cadena")
        if not isinstance(emails, int) or emails < 0:
            raise ValidacionException("Emails afectados debe ser un entero no negativo")

    def calcular_riesgo(self):
        """Calcula riesgo: ALTO si >100 emails, MEDIO en caso contrario."""
        self.riesgo = "ALTO" if self.emails_afectados > 100 else "MEDIO"
        return self.riesgo
    

    def get_recomendaciones(self):
        """Retorna recomendaciones estándar para phishing."""
        return ["Bloquear URL", "Notificar IT"]


class IncidenciaMalware(Incidencia):
    """Incidencia de malware: infección por software malicioso.

    Atributos adicionales:
        tipo_malware (str): Tipo de malware (ej. virus, trojan).
        sistemas_afectados (int): Número de sistemas infectados.
    """

    def __init__(self, id, titulo, desc, fecha, afec, tipo_malware, sistemas_afectados):
        """Inicializa una incidencia de malware con validación específica."""
        super().__init__(id, titulo, desc, fecha, afec)
        self.validar_malware(tipo_malware, sistemas_afectados)
        self.tipo_malware = tipo_malware
        self.sistemas_afectados = sistemas_afectados

    def validar_malware(self, tipo, sistemas):
        """Valida parámetros específicos de malware."""
        if not isinstance(tipo, str):
            raise ValidacionException("Tipo de malware debe ser una cadena")
        if not isinstance(sistemas, int) or sistemas < 0:
            raise ValidacionException("Sistemas afectados debe ser un entero no negativo")

    def calcular_riesgo(self):
        """Calcula riesgo: CRITICO si >5 sistemas, ALTO en caso contrario."""
        self.riesgo = "CRITICO" if self.sistemas_afectados > 5 else "ALTO"
        return self.riesgo

    def get_recomendaciones(self):
        """Retorna recomendaciones estándar para malware."""
        return ["Aislar equipos", "Escaneo completo"]


class IncidenciaFuerzaBruta(Incidencia):
    """Incidencia de fuerza bruta: intentos repetidos de acceso no autorizado.

    Atributos adicionales:
        intentos (int): Número de intentos realizados.
        ip_origen (str): Dirección IP del atacante.
    """

    def __init__(self, id, titulo, desc, fecha, afec, intentos, ip_origen):
        """Inicializa una incidencia de fuerza bruta con validación específica."""
        super().__init__(id, titulo, desc, fecha, afec)
        self.validar_fuerza_bruta(intentos, ip_origen)
        self.intentos = intentos
        self.ip_origen = ip_origen

    def validar_fuerza_bruta(self, intentos, ip):
        """Valida parámetros específicos de fuerza bruta."""
        if not isinstance(intentos, int) or intentos < 0:
            raise ValidacionException("Intentos debe ser un entero no negativo")
        if not isinstance(ip, str):
            raise ValidacionException("IP origen debe ser una cadena")

    def calcular_riesgo(self):
        """Calcula riesgo: ALTO si >500 intentos, MEDIO en caso contrario."""
        self.riesgo = "ALTO" if self.intentos > 500 else "MEDIO"
        return self.riesgo

    def get_recomendaciones(self):
        """Retorna recomendaciones estándar para fuerza bruta."""
        return ["Bloquear IP", "Activar 2FA"]


class IncidenciaFugaDatos(Incidencia):
    """Incidencia de fuga de datos: exposición no autorizada de información.

    Atributos adicionales:
        registros_expuestos (int): Número de registros afectados.
        datos_sensibles (bool): Si los datos incluyen información sensible.
    """

    def __init__(self, id, titulo, desc, fecha, afec, registros_expuestos, datos_sensibles):
        """Inicializa una incidencia de fuga de datos con validación específica."""
        super().__init__(id, titulo, desc, fecha, afec)
        self.validar_fuga_datos(registros_expuestos, datos_sensibles)
        self.registros_expuestos = registros_expuestos
        self.datos_sensibles = datos_sensibles

    def validar_fuga_datos(self, registros, sensibles):
        """Valida parámetros específicos de fuga de datos."""
        if not isinstance(registros, int) or registros < 0:
            raise ValidacionException("Registros expuestos debe ser un entero no negativo")
        if not isinstance(sensibles, bool):
            raise ValidacionException("Datos sensibles debe ser un booleano")

    def calcular_riesgo(self):
        """Calcula riesgo: CRITICO si datos sensibles, ALTO en caso contrario."""
        self.riesgo = "CRITICO" if self.datos_sensibles else "ALTO"
        return self.riesgo

    def get_recomendaciones(self):
        """Retorna recomendaciones estándar para fuga de datos."""
        return ["Aviso legal", "Cambio de llaves"]


class IncidenciaAccesoNoAutorizado(Incidencia):
    """Incidencia de acceso no autorizado: entrada a sistemas sin permiso.

    Atributos adicionales:
        usuario (str): Usuario que realizó el acceso.
        recurso_accedido (str): Recurso o sistema accedido.
    """

    def __init__(self, id, titulo, desc, fecha, afec, usuario, recurso_accedido):
        """Inicializa una incidencia de acceso no autorizado con validación específica."""
        super().__init__(id, titulo, desc, fecha, afec)
        self.validar_acceso_no_autorizado(usuario, recurso_accedido)
        self.usuario = usuario
        self.recurso_accedido = recurso_accedido

    def validar_acceso_no_autorizado(self, usuario, recurso):
        """Valida parámetros específicos de acceso no autorizado."""
        if not isinstance(usuario, str):
            raise ValidacionException("Usuario debe ser una cadena")
        if not isinstance(recurso, str):
            raise ValidacionException("Recurso accedido debe ser una cadena")

    def calcular_riesgo(self):
        """Calcula riesgo: siempre ALTO para accesos no autorizados."""
        self.riesgo = "ALTO"
        return self.riesgo

    def get_recomendaciones(self):
        """Retorna recomendaciones estándar para acceso no autorizado."""
        return ["Revocar permisos", "Auditar logs"]

    