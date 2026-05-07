import pandas as pd
import os

class GestorIncidencias:
    def __init__(self):
        # Lista donde guardaremos los OBJETOS de las clases (Phishing, Malware, etc.)
        self.incidencias = []

    def registrar(self, incidencia):
        [span_2](start_span)"""Añade una incidencia a la lista[span_2](end_span)."""
        self.incidencias.append(incidencia)

    def guardar_csv(self, ruta="data/incidencias.csv"):
        [span_3](start_span)"""Convierte los objetos a una tabla y los guarda en un archivo CSV[span_3](end_span)."""
        # Creamos una lista de diccionarios con los datos de los objetos
        datos = []
        for inc in self.incidencias:
            d = {
                "ID": inc.id,
                "Título": inc.titulo,
                "Descripción": inc.descripcion,
                "Fecha": inc.fecha,
                "Afectados": inc.afectados,
                "Tipo": type(inc).__name__, # Esto guarda si es Phishing, Malware, etc.
                [span_4](start_span)"Riesgo": inc.calcular_riesgo(), # Polimorfismo en acción[span_4](end_span)
                "Recomendación": inc.get_recomendaciones()
            }
            datos.append(d)
        
        df = pd.DataFrame(datos)
        # Creamos la carpeta 'data' si no existe
        os.makedirs(os.path.dirname(ruta), exist_ok=True)
        df.to_csv(ruta, index=False, encoding='utf-8')

    def cargar_datos(self, ruta="data/incidencias.csv"):
        [span_5](start_span)"""Lee el CSV y devuelve un DataFrame para que Streamlit lo muestre[span_5](end_span)."""
        if os.path.exists(ruta):
            return pd.read_csv(ruta)
        return pd.DataFrame() # Devuelve tabla vacía si no hay archivo

    def get_estadisticas(self):
        [span_6](start_span)"""Calcula cuántas incidencias hay de cada nivel de riesgo[span_6](end_span)."""
        df = self.cargar_datos()
        if not df.empty:
            return df['Riesgo'].value_counts()
        return None