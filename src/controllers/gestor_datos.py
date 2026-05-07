import os
import sys
import json
import pandas as pd

# Ajuste para ejecutar este módulo como script desde cualquier carpeta.
ruta_raiz = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if ruta_raiz not in sys.path:
    sys.path.insert(0, ruta_raiz)

from src.models.incidencia import (
    Incidencia,
    IncidenciaPhishing,
    IncidenciaMalware,
    IncidenciaFuerzaBruta,
    IncidenciaFugaDatos,
    IncidenciaAccesoNoAutorizado,
)
from src.utils.excepciones import GestorDatosException, ValidacionException


class GestorIncidencias:
    def __init__(self, ruta_csv="data/incidencias.csv"):
        self.incidencias = []
        self.ruta_csv = ruta_csv
        self.cargar_desde_csv()

    def registrar(self, incidencia):
        """Añade una incidencia válida al gestor."""
        if not isinstance(incidencia, Incidencia):
            raise GestorDatosException("Solo se pueden registrar objetos de tipo Incidencia")

        if any(item.id == incidencia.id for item in self.incidencias):
            raise ValidacionException(f"Ya existe una incidencia con ID {incidencia.id}")

        self.incidencias.append(incidencia)
        return incidencia

    def listar(self):
        """Devuelve la lista de incidencias registradas."""
        return list(self.incidencias)

    def buscar_por_id(self, id_incidencia):
        """Busca una incidencia por su ID."""
        for inc in self.incidencias:
            if inc.id == id_incidencia:
                return inc
        return None

    def filtrar_por_tipo(self, tipo):
        """Filtra incidencias por tipo de clase."""
        return [inc for inc in self.incidencias if type(inc).__name__ == tipo]

    def filtrar_por_riesgo(self, riesgo):
        """Filtra incidencias por nivel de riesgo."""
        return [inc for inc in self.incidencias if inc.calcular_riesgo() == riesgo]

    def limpiar_todas(self):
        """Elimina todas las incidencias del gestor."""
        self.incidencias = []

    def eliminar_por_id(self, id_incidencia):
        """Elimina una incidencia por ID."""
        self.incidencias = [inc for inc in self.incidencias if inc.id != id_incidencia]

    def to_dataframe(self):
        """Convierte la lista de incidencias a un DataFrame."""
        datos = []
        for inc in self.incidencias:
            datos.append({
                "ID": inc.id,
                "Título": inc.titulo,
                "Descripción": inc.descripcion,
                "Fecha": inc.fecha,
                "Afectados": inc.afectados,
                "Tipo": type(inc).__name__,
                "Riesgo": inc.calcular_riesgo(),
                "Recomendación": ", ".join(inc.get_recomendaciones()),
            })
        return pd.DataFrame(datos)

    def guardar_csv(self, ruta=None):
        """Guarda todas las incidencias en un archivo CSV."""
        ruta = ruta or self.ruta_csv
        df = self.to_dataframe()
        os.makedirs(os.path.dirname(ruta), exist_ok=True)
        df.to_csv(ruta, index=False, encoding="utf-8")
        return ruta

    def guardar_json(self, ruta="data/incidencias.json"):
        """Guarda todas las incidencias en un archivo JSON."""
        datos = []
        for inc in self.incidencias:
            datos.append({
                "id": inc.id,
                "titulo": inc.titulo,
                "descripcion": inc.descripcion,
                "fecha": inc.fecha,
                "afectados": inc.afectados,
                "tipo": type(inc).__name__,
                "riesgo": inc.calcular_riesgo(),
                "recomendaciones": inc.get_recomendaciones(),
            })

        os.makedirs(os.path.dirname(ruta), exist_ok=True)
        with open(ruta, "w", encoding="utf-8") as archivo:
            json.dump(datos, archivo, ensure_ascii=False, indent=2)
        return ruta

    def cargar_desde_csv(self, ruta=None):
        """Carga incidencias desde un archivo CSV y las convierte en objetos."""
        ruta = ruta or self.ruta_csv
        self.incidencias = []

        if not os.path.exists(ruta):
            return []

        df = pd.read_csv(ruta)
        for _, fila in df.iterrows():
            incidencia = self._crear_incidencia_desde_fila(fila)
            if incidencia:
                self.incidencias.append(incidencia)
        return self.incidencias

    def cargar_desde_json(self, ruta="data/incidencias.json"):
        """Carga incidencias desde un archivo JSON y las convierte en objetos."""
        self.incidencias = []

        if not os.path.exists(ruta):
            return []

        with open(ruta, "r", encoding="utf-8") as archivo:
            try:
                datos = json.load(archivo)
            except json.JSONDecodeError:
                return []  # Si el JSON está vacío o inválido, devolver lista vacía

        for item in datos:
            incidencia = self._crear_incidencia_desde_dict(item)
            if incidencia:
                self.incidencias.append(incidencia)
        return self.incidencias

    def _crear_incidencia_desde_fila(self, fila):
        return self._crear_incidencia_desde_dict(fila.to_dict())

    def _crear_incidencia_desde_dict(self, datos):
        def safe_str(value, default=""):
            if pd.isna(value):
                return default
            return str(value).strip()
        
        tipo = safe_str(datos.get("Tipo") or datos.get("tipo", ""))
        if tipo == "IncidenciaPhishing":
            return IncidenciaPhishing(
                int(datos.get("ID", 0)),
                safe_str(datos.get("Título") or datos.get("titulo", "")),
                safe_str(datos.get("Descripción") or datos.get("descripcion", "")),
                safe_str(datos.get("Fecha") or datos.get("fecha", "")),
                int(datos.get("Afectados", 0)),
                safe_str(datos.get("url_maliciosa", "")),
                int(datos.get("emails_afectados", datos.get("emails_afectados", 0))),
            )
        if tipo == "IncidenciaMalware":
            return IncidenciaMalware(
                int(datos.get("ID", 0)),
                safe_str(datos.get("Título") or datos.get("titulo", "")),
                safe_str(datos.get("Descripción") or datos.get("descripcion", "")),
                safe_str(datos.get("Fecha") or datos.get("fecha", "")),
                int(datos.get("Afectados", 0)),
                safe_str(datos.get("tipo_malware", "")),
                int(datos.get("sistemas_afectados", 0)),
            )
        if tipo == "IncidenciaFuerzaBruta":
            return IncidenciaFuerzaBruta(
                int(datos.get("ID", 0)),
                safe_str(datos.get("Título") or datos.get("titulo", "")),
                safe_str(datos.get("Descripción") or datos.get("descripcion", "")),
                safe_str(datos.get("Fecha") or datos.get("fecha", "")),
                int(datos.get("Afectados", 0)),
                int(datos.get("intentos", 0)),
                safe_str(datos.get("ip_origen", "")),
            )
        if tipo == "IncidenciaFugaDatos":
            return IncidenciaFugaDatos(
                int(datos.get("ID", 0)),
                safe_str(datos.get("Título") or datos.get("titulo", "")),
                safe_str(datos.get("Descripción") or datos.get("descripcion", "")),
                safe_str(datos.get("Fecha") or datos.get("fecha", "")),
                int(datos.get("Afectados", 0)),
                int(datos.get("registros_expuestos", 0)),
                bool(datos.get("datos_sensibles", False)),
            )
        if tipo == "IncidenciaAccesoNoAutorizado":
            return IncidenciaAccesoNoAutorizado(
                int(datos.get("ID", 0)),
                safe_str(datos.get("Título") or datos.get("titulo", "")),
                safe_str(datos.get("Descripción") or datos.get("descripcion", "")),
                safe_str(datos.get("Fecha") or datos.get("fecha", "")),
                int(datos.get("Afectados", 0)),
                safe_str(datos.get("usuario", "")),
                safe_str(datos.get("recurso_accedido", "")),
            )
        return None

    def get_estadisticas(self):
        """Calcula estadísticas básicas por riesgo y tipo."""
        df = self.to_dataframe()
        if df.empty:
            return {}

        return {
            "total": len(df),
            "por_riesgo": df["Riesgo"].value_counts().to_dict(),
            "por_tipo": df["Tipo"].value_counts().to_dict(),
        }
