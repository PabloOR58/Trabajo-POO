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
        if not isinstance(incidencia, Incidencia):
            raise GestorDatosException("Solo se pueden registrar objetos de tipo Incidencia")

        if any(item.id == incidencia.id for item in self.incidencias):
            raise ValidacionException(f"Ya existe una incidencia con ID {incidencia.id}")

        self.incidencias.append(incidencia)
        return incidencia

    def listar(self):
        return list(self.incidencias)

    def buscar_por_id(self, id_incidencia):
        for inc in self.incidencias:
            if inc.id == id_incidencia:
                return inc
        return None

    def filtrar_por_tipo(self, tipo):
        return [inc for inc in self.incidencias if type(inc).__name__ == tipo]

    def filtrar_por_riesgo(self, riesgo):
        return [inc for inc in self.incidencias if inc.calcular_riesgo() == riesgo]

    def limpiar_todas(self):
        self.incidencias = []

    def eliminar_por_id(self, id_incidencia):
        self.incidencias = [inc for inc in self.incidencias if inc.id != id_incidencia]

    def to_dataframe(self):
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
        ruta = ruta or self.ruta_csv
        df = self.to_dataframe()
        os.makedirs(os.path.dirname(ruta), exist_ok=True)
        columnas = ["ID", "Título", "Descripción", "Fecha", "Afectados", "Tipo", "Riesgo", "Recomendación"]
        df.to_csv(ruta, index=False, encoding="utf-8", columns=columnas, lineterminator="\n")
        return ruta

    def guardar_json(self, ruta="data/incidencias.json"):
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
        # Convierte un valor a string de forma segura
        def safe_str(value, default=""):
            # Si el valor es NaN (vacío en pandas), devuelve valor por defecto
            if pd.isna(value):
                return default
            return str(value).strip()
        # Convierte un valor a entero de forma segura
        
        def safe_int(value, default=0):
        # Convierte un valor a entero de forma segura  
            if pd.isna(value) or value == "":
                # Si está vacío o es NaN, devuelve el valor por defec
                return default
            try:
                return int(value)
                # Intenta convertir a entero
            except (ValueError, TypeError):
                # Si falla la conversión, devuelve el valor por defecto
                return default
        # Busca una clave dentro del diccionario (acepta varias opciones)
        def get_pair(*keys, default=""):
            for key in keys:
                # Recorre todas las posibles claves
                if key in datos and datos[key] is not None:
                    # Si la clave existe y no es None, la devuelve
                    return datos[key]
            return default
            # Si no encuentra ninguna clave válida, devuelve el valor por defecto

        tipo = safe_str(get_pair("Tipo", "tipo", default=""))
        if tipo == "IncidenciaPhishing":
            return IncidenciaPhishing(
                safe_int(get_pair("ID", "id", default=0)),
                safe_str(get_pair("Título", "titulo", default="")),
                safe_str(get_pair("Descripción", "descripcion", default="")),
                safe_str(get_pair("Fecha", "fecha", default="")),
                safe_int(get_pair("Afectados", "afectados", default=0)),
                safe_str(get_pair("url_maliciosa", "url_maliciosa", default="")),
                safe_int(get_pair("emails_afectados", "emails_afectados", default=0)),
            )
        if tipo == "IncidenciaMalware":
            return IncidenciaMalware(
                safe_int(get_pair("ID", "id", default=0)),
                safe_str(get_pair("Título", "titulo", default="")),
                safe_str(get_pair("Descripción", "descripcion", default="")),
                safe_str(get_pair("Fecha", "fecha", default="")),
                safe_int(get_pair("Afectados", "afectados", default=0)),
                safe_str(get_pair("tipo_malware", "tipo_malware", default="")),
                safe_int(get_pair("sistemas_afectados", "sistemas_afectados", default=0)),
            )
        if tipo == "IncidenciaFuerzaBruta":
            return IncidenciaFuerzaBruta(
                safe_int(get_pair("ID", "id", default=0)),
                safe_str(get_pair("Título", "titulo", default="")),
                safe_str(get_pair("Descripción", "descripcion", default="")),
                safe_str(get_pair("Fecha", "fecha", default="")),
                safe_int(get_pair("Afectados", "afectados", default=0)),
                safe_int(get_pair("intentos", "intentos", default=0)),
                safe_str(get_pair("ip_origen", "ip_origen", default="")),
            )
        if tipo == "IncidenciaFugaDatos":
            return IncidenciaFugaDatos(
                safe_int(get_pair("ID", "id", default=0)),
                safe_str(get_pair("Título", "titulo", default="")),
                safe_str(get_pair("Descripción", "descripcion", default="")),
                safe_str(get_pair("Fecha", "fecha", default="")),
                safe_int(get_pair("Afectados", "afectados", default=0)),
                safe_int(get_pair("registros_expuestos", "registros_expuestos", default=0)),
                bool(get_pair("datos_sensibles", "datos_sensibles", default=False)),
            )
        if tipo == "IncidenciaAccesoNoAutorizado":
            return IncidenciaAccesoNoAutorizado(
                safe_int(get_pair("ID", "id", default=0)),
                safe_str(get_pair("Título", "titulo", default="")),
                safe_str(get_pair("Descripción", "descripcion", default="")),
                safe_str(get_pair("Fecha", "fecha", default="")),
                safe_int(get_pair("Afectados", "afectados", default=0)),
                safe_str(get_pair("usuario", "usuario", default="")),
                safe_str(get_pair("recurso_accedido", "recurso_accedido", default="")),
            )
        return None

    def get_estadisticas(self):
        df = self.to_dataframe()
        if df.empty:
            return {}

        return {
            "total": len(df),
            "por_riesgo": df["Riesgo"].value_counts().to_dict(),
            "por_tipo": df["Tipo"].value_counts().to_dict(),
            
        }
