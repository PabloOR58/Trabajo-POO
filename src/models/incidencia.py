from abc import ABC, abstractmethod

class Incidencia(ABC):
    def __init__(self, id, titulo, descripcion, fecha, afectados):
        self.id = id
        self.titulo = titulo
        self.descripcion = descripcion
        self.fecha = fecha
        self.afectados = afectados

    @abstractmethod
    def calcular_riesgo(self):
        pass

    @abstractmethod
    def get_recomendaciones(self):
        pass



class IncidenciaPhishing(Incidencia):
    def __init__(self, id, titulo, desc, fecha, afec, url_maliciosa, emails_afectados):
        super().__init__(id, titulo, desc, fecha, afec)
        self.url_maliciosa = url_maliciosa
        self.emails_afectados = emails_afectados

    def calcular_riesgo(self):
        return "ALTO" if self.emails_afectados > 100 else "MEDIO"

    def get_recomendaciones(self):
        return ["Bloquear URL", "Notificar IT"]

class IncidenciaMalware(Incidencia):
    def __init__(self, id, titulo, desc, fecha, afec, tipo_malware, sistemas_afectados):
        super().__init__(id, titulo, desc, fecha, afec)
        self.tipo_malware = tipo_malware
        self.sistemas_afectados = sistemas_afectados

    def calcular_riesgo(self):
        return "CRITICO" if self.sistemas_afectados > 5 else "ALTO"

    def get_recomendaciones(self):
        return ["Aislar equipos", "Escaneo completo"]

class IncidenciaFuerzaBruta(Incidencia):
    def __init__(self, id, titulo, desc, fecha, afec, intentos, ip_origen):
        super().__init__(id, titulo, desc, fecha, afec)
        self.intentos = intentos
        self.ip_origen = ip_origen

    def calcular_riesgo(self):
        return "ALTO" if self.intentos > 500 else "MEDIO"

    def get_recomendaciones(self):
        return ["Bloquear IP", "Activar 2FA"]

class IncidenciaFugaDatos(Incidencia):
    def __init__(self, id, titulo, desc, fecha, afec, registros_expuestos, datos_sensibles):
        super().__init__(id, titulo, desc, fecha, afec)
        self.registros_expuestos = registros_expuestos
        self.datos_sensibles = datos_sensibles

    def calcular_riesgo(self):
        return "CRITICO" if self.datos_sensibles else "ALTO"

    def get_recomendaciones(self):
        return ["Aviso legal", "Cambio de llaves"]

class IncidenciaAccesoNoAutorizado(Incidencia):
    def __init__(self, id, titulo, desc, fecha, afec, usuario, recurso_accedido):
        super().__init__(id, titulo, desc, fecha, afec)
        self.usuario = usuario
        self.recurso_accedido = recurso_accedido

    def calcular_riesgo(self):
        return "ALTO"

    def get_recomendaciones(self):
        return ["Revocar permisos", "Auditar logs"]