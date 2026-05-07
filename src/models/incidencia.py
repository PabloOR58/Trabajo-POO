from abc import ABC, abstractmethod
from src.utils.excepciones import ValidacionException

class Incidencia(ABC):
    def __init__(self, id, titulo, descripcion, fecha, afectados):
        self.validar_datos(id, titulo, descripcion, fecha, afectados)
        self.id = id
        self.titulo = titulo
        self.descripcion = descripcion
        self.fecha = fecha
        self.afectados = afectados

    def validar_datos(self, id, titulo, descripcion, fecha, afectados):
        if not isinstance(id, str) or not id.strip():
            raise ValidacionException("ID debe ser una cadena no vacía")
        if not isinstance(titulo, str) or not titulo.strip():
            raise ValidacionException("Título debe ser una cadena no vacía")
        if not isinstance(descripcion, str) or not descripcion.strip():
            raise ValidacionException("Descripción debe ser una cadena no vacía")
        if not isinstance(fecha, str) or not fecha.strip():
            raise ValidacionException("Fecha debe ser una cadena no vacía")
        if not isinstance(afectados, int) or afectados < 0:
            raise ValidacionException("Afectados debe ser un entero no negativo")

    @abstractmethod
    def calcular_riesgo(self):
        pass

    @abstractmethod
    def get_recomendaciones(self):
        pass

class grado_incidencia:
    BAJO = "BAJO"
    MEDIO = "MEDIO"
    ALTO = "ALTO"
    CRITICO = "CRITICO"

class IncidenciaPhishing(Incidencia):
    def __init__(self, id, titulo, desc, fecha, afec, url_maliciosa, emails_afectados):
        super().__init__(id, titulo, desc, fecha, afec)
        self.validar_phishing(url_maliciosa, emails_afectados)
        self.url_maliciosa = url_maliciosa
        self.emails_afectados = emails_afectados

    def validar_phishing(self, url, emails):
        if not isinstance(url, str) or not url.strip():
            raise ValidacionException("URL maliciosa debe ser una cadena no vacía")
        if not isinstance(emails, int) or emails < 0:
            raise ValidacionException("Emails afectados debe ser un entero no negativo")

    def calcular_riesgo(self):
        return "ALTO" if self.emails_afectados > 100 else "MEDIO"

    def get_recomendaciones(self):
        return ["Bloquear URL", "Notificar IT"]

class IncidenciaMalware(Incidencia):
    def __init__(self, id, titulo, desc, fecha, afec, tipo_malware, sistemas_afectados):
        super().__init__(id, titulo, desc, fecha, afec)
        self.validar_malware(tipo_malware, sistemas_afectados)
        self.tipo_malware = tipo_malware
        self.sistemas_afectados = sistemas_afectados

    def validar_malware(self, tipo, sistemas):
        if not isinstance(tipo, str) or not tipo.strip():
            raise ValidacionException("Tipo de malware debe ser una cadena no vacía")
        if not isinstance(sistemas, int) or sistemas < 0:
            raise ValidacionException("Sistemas afectados debe ser un entero no negativo")

    def calcular_riesgo(self):
        return "CRITICO" if self.sistemas_afectados > 5 else "ALTO"

    def get_recomendaciones(self):
        return ["Aislar equipos", "Escaneo completo"]

class IncidenciaFuerzaBruta(Incidencia):
    def __init__(self, id, titulo, desc, fecha, afec, intentos, ip_origen):
        super().__init__(id, titulo, desc, fecha, afec)
        self.validar_fuerza_bruta(intentos, ip_origen)
        self.intentos = intentos
        self.ip_origen = ip_origen

    def validar_fuerza_bruta(self, intentos, ip):
        if not isinstance(intentos, int) or intentos < 0:
            raise ValidacionException("Intentos debe ser un entero no negativo")
        if not isinstance(ip, str) or not ip.strip():
            raise ValidacionException("IP origen debe ser una cadena no vacía")

    def calcular_riesgo(self):
        return "ALTO" if self.intentos > 500 else "MEDIO"

    def get_recomendaciones(self):
        return ["Bloquear IP", "Activar 2FA"]

class IncidenciaFugaDatos(Incidencia):
    def __init__(self, id, titulo, desc, fecha, afec, registros_expuestos, datos_sensibles):
        super().__init__(id, titulo, desc, fecha, afec)
        self.validar_fuga_datos(registros_expuestos, datos_sensibles)
        self.registros_expuestos = registros_expuestos
        self.datos_sensibles = datos_sensibles

    def validar_fuga_datos(self, registros, sensibles):
        if not isinstance(registros, int) or registros < 0:
            raise ValidacionException("Registros expuestos debe ser un entero no negativo")
        if not isinstance(sensibles, bool):
            raise ValidacionException("Datos sensibles debe ser un booleano")

    def calcular_riesgo(self):
        return "CRITICO" if self.datos_sensibles else "ALTO"

    def get_recomendaciones(self):
        return ["Aviso legal", "Cambio de llaves"]

class IncidenciaAccesoNoAutorizado(Incidencia):
    def __init__(self, id, titulo, desc, fecha, afec, usuario, recurso_accedido):
        super().__init__(id, titulo, desc, fecha, afec)
        self.validar_acceso_no_autorizado(usuario, recurso_accedido)
        self.usuario = usuario
        self.recurso_accedido = recurso_accedido

    def validar_acceso_no_autorizado(self, usuario, recurso):
        if not isinstance(usuario, str) or not usuario.strip():
            raise ValidacionException("Usuario debe ser una cadena no vacía")
        if not isinstance(recurso, str) or not recurso.strip():
            raise ValidacionException("Recurso accedido debe ser una cadena no vacía")

    def calcular_riesgo(self):
        return "ALTO"

    def get_recomendaciones(self):
        return ["Revocar permisos", "Auditar logs"]