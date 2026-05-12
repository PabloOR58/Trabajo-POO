#Este archivo gestiona el ciclo de vida de los datos

import os #Es el que maneja carpetas y verifica los archivos JSON/CSV ya están creados
import sys #Es el que maneja las rutas para importar los módulos del proyecto sin importar desde dónde se ejecute el script
import json #Es el que maneja la lectura y escritura de archivos JSON, utilizado para guardar y cargar las incidencias en formato JSON
import pandas as pd #Es el que maneja la lectura y escritura de archivos CSV, utilizado para guardar y cargar las incidencias en formato CSV, así como para convertir la lista de incidencias a un DataFrame para análisis y visualización.

# Ajuste para ejecutar este módulo como script desde cualquier carpeta.
ruta_raiz = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')) #Obtenemos la ruta raíz del proyecto, subiendo dos niveles desde la ubicación actual del archivo.
if ruta_raiz not in sys.path: #Si la ruta raíz no está ya en sys.path, la añadimos al inicio para asegurar que las importaciones del proyecto funcionen correctamente sin importar desde dónde se ejecute el script.
    sys.path.insert(0, ruta_raiz) #Esto permite que los módulos del proyecto se importen correctamente, incluso si este archivo se ejecuta directamente desde la línea de comandos o desde un entorno de desarrollo que no tiene la ruta del proyecto configurada. Es una práctica común para asegurar la portabilidad y facilidad de uso del código.

from src.models.incidencia import ( #Importamos las clases de incidencia para poder crear objetos de estas clases a partir de los datos cargados desde CSV o JSON, así como para validar que los objetos registrados sean del tipo correcto.
    Incidencia,
    IncidenciaPhishing,
    IncidenciaMalware, 
    IncidenciaFuerzaBruta,
    IncidenciaFugaDatos,
    IncidenciaAccesoNoAutorizado,
)
from src.utils.excepciones import GestorDatosException, ValidacionException #Importamos las excepciones personalizadas para manejar errores específicos relacionados con la gestión de datos, como intentar registrar un objeto que no es una incidencia o intentar registrar una incidencia con un ID duplicado.


class GestorIncidencias: 
    def __init__(self, ruta_csv="data/incidencias.csv"): #El constructor de la clase GestorIncidencias inicializa una lista vacía para almacenar las incidencias y define la ruta del archivo CSV donde se guardarán las incidencias. Luego, llama al método cargar_desde_csv para cargar cualquier incidencia previamente guardada en el archivo CSV al iniciar el gestor.
        
        self.incidencias = []
        self.ruta_csv = ruta_csv
        self.cargar_desde_csv()

    def registrar(self, incidencia):
        """Añade una incidencia válida al gestor."""
        if not isinstance(incidencia, Incidencia): #Validamos que el objeto que se intenta registrar sea una instancia de la clase Incidencia o sus subclases. Si no es así, se lanza una excepción GestorDatosException para indicar que solo se pueden registrar objetos de tipo Incidencia.
            raise GestorDatosException("Solo se pueden registrar objetos de tipo Incidencia")

        if any(item.id == incidencia.id for item in self.incidencias): #Validamos que no exista ya una incidencia con el mismo ID en la lista de incidencias. Si se encuentra una incidencia con el mismo ID, se lanza una excepción ValidacionException para indicar que ya existe una incidencia con ese ID, evitando así duplicados en el registro.
            raise ValidacionException(f"Ya existe una incidencia con ID {incidencia.id}")

        self.incidencias.append(incidencia) #Si la incidencia es válida y no hay duplicados, se añade a la lista de incidencias del gestor. Luego, se devuelve la incidencia registrada para confirmar que se ha añadido correctamente.
        return incidencia

    def listar(self):
        """Devuelve la lista de incidencias registradas."""
        return list(self.incidencias)

    def buscar_por_id(self, id_incidencia):
        """Busca una incidencia por su ID."""
        for inc in self.incidencias: #Iteramos sobre la lista de incidencias para encontrar una incidencia cuyo ID coincida con el ID proporcionado. Si se encuentra una coincidencia, se devuelve esa incidencia. Si no se encuentra ninguna incidencia con el ID especificado, se devuelve None para indicar que no se encontró la incidencia.
            if inc.id == id_incidencia: 
                return inc
        return None

    def filtrar_por_tipo(self, tipo):
        """Filtra incidencias por tipo de clase."""
        return [inc for inc in self.incidencias if type(inc).__name__ == tipo] #Filtra la lista de incidencias para devolver solo aquellas que sean del tipo de clase especificado. El tipo se compara con el nombre de la clase de cada incidencia utilizando type(inc).__name__. Esto permite filtrar por tipos específicos como "IncidenciaPhishing", "IncidenciaMalware", etc., devolviendo una lista de incidencias que coincidan con el tipo solicitado.

    def filtrar_por_riesgo(self, riesgo):
        """Filtra incidencias por nivel de riesgo."""
        return [inc for inc in self.incidencias if inc.calcular_riesgo() == riesgo]

    def limpiar_todas(self):
        """Elimina todas las incidencias del gestor."""
        self.incidencias = [] #Limpia la lista de incidencias, eliminando todas las incidencias registradas en el gestor. Esto es útil para reiniciar el estado del gestor o eliminar datos antiguos.

    def eliminar_por_id(self, id_incidencia):
        """Elimina una incidencia por ID."""
        self.incidencias = [inc for inc in self.incidencias if inc.id != id_incidencia] #Elimina una incidencia específica de la lista de incidencias utilizando su ID. Se crea una nueva lista que incluye solo aquellas incidencias cuyo ID no coincide con el ID proporcionado, effectively eliminando la incidencia con el ID especificado del gestor. Si no se encuentra ninguna incidencia con ese ID, la lista de incidencias permanece sin cambios.

    def to_dataframe(self):
        """Convierte la lista de incidencias a un DataFrame."""
        datos = []
        for inc in self.incidencias: #Iteramos sobre la lista de incidencias para construir una lista de diccionarios, donde cada diccionario representa una incidencia con sus atributos relevantes. Esto incluye el ID, título, descripción, fecha, número de afectados, tipo de incidencia (obtenido a través del nombre de la clase), nivel de riesgo calculado y recomendaciones asociadas. Esta lista de diccionarios se utiliza para crear un DataFrame de pandas que facilita el análisis y visualización de los datos.
            datos.append({
                "ID": inc.id,
                "Título": inc.titulo,
                "Descripción": inc.descripcion,
                "Fecha": inc.fecha,
                "Afectados": inc.afectados,
                "Tipo": type(inc).__name__,
                "Riesgo": inc.calcular_riesgo(),
                "Recomendación": ", ".join(inc.get_recomendaciones()),  #Las recomendaciones se obtienen como una lista de strings, por lo que se unen en una sola cadena separada por comas para facilitar su visualización en el DataFrame.
            })
        return pd.DataFrame(datos)  #Devuelve un DataFrame de pandas construido a partir de la lista de incidencias, donde cada fila representa una incidencia y las columnas corresponden a los atributos definidos en el diccionario. Esto permite realizar análisis, filtrados y visualizaciones de los datos de las incidencias de manera más eficiente utilizando las funcionalidades de pandas.

    def guardar_csv(self, ruta=None):
        """Guarda todas las incidencias en un archivo CSV."""
        ruta = ruta or self.ruta_csv #Si no se proporciona una ruta específica para guardar el archivo CSV, se utiliza la ruta predeterminada definida en el atributo ruta_csv del gestor. Esto permite flexibilidad para guardar en diferentes ubicaciones si es necesario, pero también proporciona una ubicación predeterminada para facilitar el uso.
        df = self.to_dataframe()
        os.makedirs(os.path.dirname(ruta), exist_ok=True)  #Asegura que el directorio donde se va a guardar el archivo CSV exista, creando cualquier directorio necesario en la ruta especificada. Esto evita errores al intentar guardar el archivo en una ubicación que no existe.
        columnas = ["ID", "Título", "Descripción", "Fecha", "Afectados", "Tipo", "Riesgo", "Recomendación"]
        df.to_csv(ruta, index=False, encoding="utf-8", columns=columnas, lineterminator="\n") #Guarda el DataFrame de incidencias en un archivo CSV en la ruta especificada. Se incluyen solo las columnas relevantes definidas en la lista columnas, se omite el índice del DataFrame, se utiliza codificación UTF-8 para soportar caracteres especiales y se especifica un terminador de línea para asegurar la compatibilidad entre diferentes sistemas operativos. Luego, se devuelve la ruta donde se guardó el archivo CSV para confirmar que se ha guardado correctamente.
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
        for _, fila in df.iterrows():  #Iteramos sobre cada fila del DataFrame cargado desde el archivo CSV para convertir cada fila en un objeto de incidencia correspondiente. Se utiliza el método iterrows() de pandas para obtener el índice y la fila como una Serie, y luego se llama al método _crear_incidencia_desde_fila para convertir esa fila en un objeto de incidencia. Si la conversión es exitosa y se obtiene un objeto de incidencia válido, se añade a la lista de incidencias del gestor. Al finalizar la iteración, se devuelve la lista completa de incidencias cargadas desde el archivo CSV.
            incidencia = self._crear_incidencia_desde_fila(fila)
            if incidencia:
                self.incidencias.append(incidencia)
        return self.incidencias

    def cargar_desde_json(self, ruta="data/incidencias.json"):
        """Carga incidencias desde un archivo JSON y las convierte en objetos."""
        self.incidencias = []

        if not os.path.exists(ruta):
            return []

        with open(ruta, "r", encoding="utf-8") as archivo: #Abrimos el archivo JSON en modo lectura con codificación UTF-8 para asegurarnos de que se puedan leer correctamente los caracteres especiales. Luego, intentamos cargar los datos del archivo utilizando json.load(). Si el archivo JSON está vacío o no es un formato válido, se captura la excepción json.JSONDecodeError y se devuelve una lista vacía para evitar errores posteriores al intentar procesar los datos. Si la carga es exitosa, se itera sobre cada elemento en los datos cargados, convirtiendo cada diccionario en un objeto de incidencia utilizando el método _crear_incidencia_desde_dict. Si la conversión es exitosa y se obtiene un objeto de incidencia válido, se añade a la lista de incidencias del gestor. Al finalizar la iteración, se devuelve la lista completa de incidencias cargadas desde el archivo JSON.
            try:
                datos = json.load(archivo)
            except json.JSONDecodeError:
                return []  
        for item in datos:
            incidencia = self._crear_incidencia_desde_dict(item)
            if incidencia:
                self.incidencias.append(incidencia)
        return self.incidencias

    def _crear_incidencia_desde_fila(self, fila):
        return self._crear_incidencia_desde_dict(fila.to_dict()) #Este método privado toma una fila de un DataFrame (que es una Serie de pandas) y la convierte en un diccionario utilizando el método to_dict(). Luego, llama al método _crear_incidencia_desde_dict para convertir ese diccionario en un objeto de incidencia correspondiente. Esto permite reutilizar la lógica de conversión tanto para filas de DataFrame como para diccionarios cargados desde JSON, centralizando la lógica de creación de objetos de incidencia en un solo método.

    def _crear_incidencia_desde_dict(self, datos):
        def safe_str(value, default=""):
            if pd.isna(value):  #Si el valor es NaN (Not a Number) o None, se devuelve un valor predeterminado (cadena vacía por defecto) para evitar errores al intentar convertirlo a cadena. Esto es útil para manejar datos faltantes o nulos que pueden estar presentes en el archivo CSV o JSON, asegurando que el proceso de creación de objetos de incidencia no falle debido a valores no válidos.
                return default
            return str(value).strip()

        def safe_int(value, default=0):
            if pd.isna(value) or value == "":
                return default
            try:
                return int(value)
            except (ValueError, TypeError):
                return default

        def get_pair(*keys, default=""): #Este método auxiliar toma una lista de posibles claves (keys) y busca en el diccionario de datos para encontrar el primer valor asociado a alguna de esas claves. Si encuentra un valor válido (no NaN ni None) para alguna de las claves, lo devuelve. Si no encuentra ningún valor válido para las claves proporcionadas, devuelve un valor predeterminado (cadena vacía por defecto). Esto es útil para manejar casos donde los datos pueden tener diferentes nombres de campo o formatos, permitiendo flexibilidad en la conversión de datos a objetos de incidencia.
            for key in keys:
                if key in datos and datos[key] is not None:
                    return datos[key]
            return default

        tipo = safe_str(get_pair("Tipo", "tipo", default="")) #Obtenemos el tipo de incidencia utilizando el método get_pair para buscar tanto "Tipo" como "tipo" en el diccionario de datos, asegurándonos de manejar casos donde el campo pueda tener diferentes nombres o formatos. Luego, se utiliza safe_str para convertir el valor obtenido a una cadena segura, manejando casos de valores faltantes o nulos. Este tipo se utiliza posteriormente para determinar qué clase de incidencia crear a partir de los datos proporcionados.
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
        """Calcula estadísticas básicas por riesgo y tipo."""
        df = self.to_dataframe()
        if df.empty: 
            return {}

        return {
            "total": len(df),
            "por_riesgo": df["Riesgo"].value_counts().to_dict(),
            "por_tipo": df["Tipo"].value_counts().to_dict(),
        }
