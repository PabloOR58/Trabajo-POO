import streamlit as st #Streamlit es una biblioteca de Python que permite crear aplicaciones web interactivas de manera sencilla y rápida, ideal para visualizar datos y construir interfaces de usuario sin necesidad de conocimientos avanzados en desarrollo web. En este código, se utiliza Streamlit para construir la interfaz gráfica del sistema de análisis de ciberseguridad, permitiendo a los usuarios registrar nuevas incidencias, visualizar el historial de amenazas y generar gráficos estadísticos de manera interactiva.
import sys #El módulo sys proporciona acceso a variables y funciones relacionadas con el intérprete de Python. En este código, se utiliza para manipular la ruta de búsqueda de módulos (sys.path) para asegurarse de que las importaciones del proyecto funcionen correctamente, especialmente al importar módulos desde diferentes directorios dentro del proyecto.
import os #El módulo os proporciona una forma de interactuar con el sistema operativo, permitiendo realizar operaciones como manipulación de archivos y directorios. En este código, se utiliza para construir rutas de archivos de manera independiente del sistema operativo, asegurando que las rutas funcionen correctamente tanto en Windows como en Mac/Linux al cargar y guardar datos de incidencias.
import pandas as pd #Pandas es una biblioteca de Python para la manipulación y análisis de datos. En este código, se utiliza para convertir la lista de incidencias en un DataFrame, lo que facilita la visualización tabular de los datos en la interfaz de Streamlit, así como para realizar operaciones de filtrado y generación de estadísticas a partir de los datos de las incidencias registradas.
import altair as alt #Altair es una biblioteca de visualización de datos declarativa para Python, que permite crear gráficos interactivos y atractivos de manera sencilla. En este código, se utiliza para generar gráficos de barras que muestran la distribución de incidencias por tipo y por nivel de riesgo, proporcionando una representación visual clara y fácil de interpretar de las estadísticas relacionadas con las amenazas registradas en el sistema de análisis de ciberseguridad.

# Configuración de rutas para Mac/Linux/Windows
ruta_raiz = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')) #Esta línea de código construye la ruta raíz del proyecto de manera dinámica, utilizando os.path para obtener la ruta absoluta del directorio actual (donde se encuentra el archivo interfaz.py) y luego navegando hacia arriba en la estructura de directorios para llegar a la raíz del proyecto. Esto permite que el código funcione correctamente en diferentes sistemas operativos (Windows, Mac, Linux) sin necesidad de modificar las rutas manualmente, ya que os.path se encarga de manejar las diferencias en los formatos de ruta entre los sistemas operativos.
if ruta_raiz not in sys.path: #Esta línea verifica si la ruta raíz del proyecto ya está incluida en la lista de rutas de búsqueda de módulos de Python (sys.path). Si no está presente, se agrega al inicio de sys.path para asegurar que las importaciones de módulos dentro del proyecto funcionen correctamente, permitiendo que el código pueda importar módulos desde la raíz del proyecto sin problemas, independientemente del sistema operativo en el que se ejecute.
    sys.path.insert(0, ruta_raiz) #Si la ruta raíz del proyecto no está ya en la lista de rutas de búsqueda de módulos (sys.path), esta línea la inserta al inicio de la lista. Esto garantiza que cuando se realicen importaciones de módulos dentro del proyecto, Python buscará primero en la ruta raíz, lo que es especialmente útil para evitar conflictos con otros módulos instalados globalmente y asegurar que se utilicen las versiones correctas de los módulos específicos del proyecto.

# Importaciones del proyecto
try: #Este bloque de código intenta importar los módulos necesarios para la aplicación, incluyendo las clases de incidencia, el gestor de datos y las excepciones personalizadas. Si ocurre un error durante la importación (por ejemplo, si algún módulo no se encuentra o hay un error en el código de los módulos), se captura la excepción ImportError y se muestra un mensaje de error en la interfaz de Streamlit, deteniendo la ejecución del programa para evitar que continúe con una configuración incompleta o incorrecta.
    from src.models.incidencia import (
        IncidenciaPhishing, IncidenciaMalware, IncidenciaFuerzaBruta,
        IncidenciaFugaDatos, IncidenciaAccesoNoAutorizado
    )
    from src.controllers.gestor_datos import GestorIncidencias
    from src.utils.excepciones import ValidacionException, GestorDatosException
except ImportError as e: #Si ocurre un error de importación, se muestra un mensaje de error en la interfaz de Streamlit indicando que hubo un error crítico al importar los módulos necesarios, junto con el mensaje de la excepción que describe el error específico. Luego, se detiene la ejecución del programa utilizando st.stop() para evitar que continúe con una configuración incompleta o incorrecta, lo que podría causar errores adicionales más adelante en la ejecución.
    st.error(f"Error de importación crítico: {e}")
    st.stop()

def main(): #La función main() es el punto de entrada principal de la aplicación de Streamlit. Dentro de esta función, se configura la página, se inicializa el gestor de incidencias, se construye la interfaz de usuario para registrar nuevas incidencias y visualizar el historial de amenazas, y se manejan las interacciones del usuario. Al final del archivo, se llama a main() para ejecutar la aplicación cuando se ejecute el script.
    st.set_page_config(page_title="Ciberseguridad UE", layout="wide")
    st.title("Sistema de Análisis de Ciberseguridad")
    st.write("Grado en Inteligencia Artificial - Universidad Europea")

    # Inicializar gestor y cargar datos
    gestor = GestorIncidencias()
    ruta_json = os.path.join(ruta_raiz, "data", "incidencias.json") #Construye la ruta al archivo JSON donde se almacenan las incidencias, utilizando os.path.join para asegurar que la ruta sea correcta en diferentes sistemas operativos. Esto permite que el programa cargue y guarde los datos de las incidencias de manera consistente, independientemente del entorno en el que se ejecute.
    if os.path.exists(ruta_json):
        gestor.cargar_desde_json()

    # =========================================================
    # SIDEBAR: REGISTRO DE INCIDENCIAS
    # =========================================================
    st.sidebar.header("📝 Nueva Incidencia") 
    
    # IMPORTANTE: El selector de tipo va FUERA del form para que la interfaz cambie al elegir
    tipo_seleccionado = st.sidebar.selectbox( #El selector de tipo de amenaza se coloca fuera del formulario para que la interfaz se actualice dinámicamente al seleccionar un tipo diferente, permitiendo que los campos específicos de cada tipo de incidencia se muestren o oculten según la selección del usuario. Esto mejora la experiencia del usuario al proporcionar una interfaz más intuitiva y adaptada a las características de cada tipo de amenaza, sin necesidad de recargar toda la página o el formulario.
        "Seleccione Tipo de Amenaza", 
        ["Phishing", "Malware", "Fuerza Bruta", "Fuga de Datos", "Acceso No Autorizado"]
    )

    with st.sidebar.form("form_registro", clear_on_submit=True): #El formulario para registrar una nueva incidencia se crea utilizando st.sidebar.form, lo que permite agrupar los campos de entrada relacionados con el registro de una incidencia y manejar su envío de manera más organizada. Al usar un formulario, se puede controlar cuándo se envían los datos ingresados por el usuario, evitando que se procesen de inmediato al cambiar los campos, y proporcionando una experiencia de usuario más fluida al permitir que el usuario complete todos los campos antes de enviar la información.
        id_inc = st.text_input("ID de Incidencia")
        titulo = st.text_input("Título")
        descripcion = st.text_area("Descripción")
        fecha_dt = st.date_input("Fecha de detección")
        afectados = st.number_input("Nº de afectados", min_value=0, step=1)
        
        st.markdown("---")
        st.subheader(f"Detalles de {tipo_seleccionado}")

        # Campos dinámicos según el tipo seleccionado fuera del form
        if tipo_seleccionado == "Phishing":
            url_maliciosa = st.text_input("URL Maliciosa")
            emails_afectados = st.number_input("Emails Afectados", min_value=0, step=1)
        elif tipo_seleccionado == "Malware":
            tipo_malware = st.text_input("Tipo de Malware (ej. Ransomware)")
            sistemas_afectados = st.number_input("Sistemas Afectados", min_value=0, step=1)
        elif tipo_seleccionado == "Fuerza Bruta":
            intentos = st.number_input("Nº de Intentos", min_value=0, step=1)
            ip_origen = st.text_input("IP de Origen")
        elif tipo_seleccionado == "Fuga de Datos":
            registros_expuestos = st.number_input("Registros Expuestos", min_value=0, step=1)
            datos_sensibles = st.checkbox("¿Incluye Datos Sensibles?")
        elif tipo_seleccionado == "Acceso No Autorizado":
            usuario = st.text_input("Usuario implicado")
            recurso_accedido = st.text_input("Recurso accedido")
        
        submit = st.form_submit_button("Registrar Incidencia")

        if submit: #Cuando el usuario hace clic en el botón "Registrar Incidencia", se ejecuta este bloque de código que intenta validar los datos ingresados, crear una nueva instancia de la clase de incidencia correspondiente al tipo seleccionado, registrar la incidencia en el gestor de datos y guardar los cambios en los archivos JSON y CSV. Si ocurre algún error durante este proceso (por ejemplo, si faltan campos obligatorios o si hay un error al guardar los datos), se captura la excepción y se muestra un mensaje de error en la interfaz de Streamlit, permitiendo al usuario corregir los errores antes de intentar registrar la incidencia nuevamente.
            try:
                # Validaciones básicas comunes
                if not id_inc or not titulo or not descripcion: #Si el ID, el título o la descripción de la incidencia están vacíos, se lanza una excepción de validación indicando que faltan campos obligatorios. Esto asegura que se proporcionen los datos mínimos necesarios para registrar una incidencia, evitando que se creen registros incompletos o sin información esencial, lo que podría dificultar el análisis y la gestión de las incidencias posteriormente.
                    raise ValidacionException("Faltan campos obligatorios (ID, Título o Descripción)")
                
                fecha_str = fecha_dt.strftime("%Y-%m-%d") #Convierte la fecha seleccionada por el usuario en un formato de cadena (YYYY-MM-DD) que es más fácil de manejar y almacenar en los archivos JSON y CSV, asegurando que la fecha se registre de manera consistente y legible en el sistema de análisis de ciberseguridad.
                nueva = None

                # Lógica de creación según tipo
                if tipo_seleccionado == "Phishing":
                    if not url_maliciosa: raise ValidacionException("URL maliciosa requerida")
                    nueva = IncidenciaPhishing(id_inc, titulo, descripcion, fecha_str, afectados, url_maliciosa, emails_afectados)
                elif tipo_seleccionado == "Malware":
                    if not tipo_malware: raise ValidacionException("Tipo de malware requerido")
                    nueva = IncidenciaMalware(id_inc, titulo, descripcion, fecha_str, afectados, tipo_malware, sistemas_afectados)
                elif tipo_seleccionado == "Fuerza Bruta":
                    if not ip_origen: raise ValidacionException("IP origen requerida")
                    nueva = IncidenciaFuerzaBruta(id_inc, titulo, descripcion, fecha_str, afectados, intentos, ip_origen)
                elif tipo_seleccionado == "Fuga de Datos":
                    nueva = IncidenciaFugaDatos(id_inc, titulo, descripcion, fecha_str, afectados, registros_expuestos, datos_sensibles)
                elif tipo_seleccionado == "Acceso No Autorizado":
                    if not usuario or not recurso_accedido: raise ValidacionException("Usuario y recurso requeridos")
                    nueva = IncidenciaAccesoNoAutorizado(id_inc, titulo, descripcion, fecha_str, afectados, usuario, recurso_accedido)
                
                if nueva:
                    gestor.registrar(nueva)
                    gestor.guardar_json()
                    gestor.guardar_csv()
                    st.sidebar.success(f"✅ {tipo_seleccionado} registrada!")
                    st.rerun()
            except (ValidacionException, GestorDatosException) as e: #Si ocurre una excepción de validación o una excepción relacionada con el gestor de datos durante el proceso de registro de una nueva incidencia, se captura la excepción y se muestra un mensaje de error en la barra lateral de Streamlit, indicando que hubo un error al registrar la incidencia junto con el mensaje específico de la excepción. Esto permite al usuario entender qué salió mal y corregir los errores antes de intentar registrar la incidencia nuevamente, mejorando la experiencia del usuario y asegurando que los datos ingresados sean válidos y consistentes.
                st.sidebar.error(f"❌ {e}")

    # =========================================================
    # CUERPO PRINCIPAL: VISUALIZACIÓN
    # =========================================================
    st.header("📊 Historial de Amenazas")
    
    df = gestor.to_dataframe()
    
    if not df.empty: #Si el DataFrame que contiene las incidencias no está vacío, se procede a mostrar la tabla de incidencias y generar las estadísticas y gráficos correspondientes. Si el DataFrame está vacío, se muestra un mensaje informativo indicando que no hay incidencias registradas aún, invitando al usuario a utilizar el panel lateral para añadir la primera incidencia. Esto mejora la experiencia del usuario al proporcionar una interfaz clara y amigable tanto cuando hay datos para mostrar como cuando aún no se han registrado incidencias.
        # Traducción de nombres de clase a etiquetas amigables
        tipo_traduccion = {
            "IncidenciaPhishing": "Phishing",
            "IncidenciaMalware": "Malware",
            "IncidenciaFuerzaBruta": "Fuerza Bruta",
            "IncidenciaFugaDatos": "Fuga de Datos",
            "IncidenciaAccesoNoAutorizado": "Acceso No Autorizado",
        }
        df["Tipo"] = df["Tipo"].map(tipo_traduccion).fillna(df["Tipo"])

        # Filtros superiores
        col_f1, col_f2 = st.columns(2) #Se crean dos columnas para colocar los filtros de tipo y riesgo de manera horizontal en la interfaz, lo que mejora la organización visual y permite a los usuarios aplicar ambos filtros de manera más intuitiva y eficiente al visualizar el historial de amenazas.
        with col_f1:
            filtro_tipo = st.selectbox("Filtrar por Tipo", ["Todos"] + list(tipo_traduccion.values())) #El filtro de tipo de amenaza se construye utilizando un selectbox que incluye la opción "Todos" seguida de las etiquetas amigables de los tipos de incidencia traducidos. Esto permite a los usuarios filtrar las incidencias por tipo específico o ver todas las incidencias sin aplicar ningún filtro, proporcionando flexibilidad en la visualización del historial de amenazas.
        with col_f2:
            filtro_riesgo = st.selectbox("Filtrar por Riesgo", ["Todos", "BAJO", "MEDIO", "ALTO", "CRITICO"])

        # Aplicar filtros al DataFrame
        if filtro_tipo != "Todos": #Si el usuario selecciona un tipo específico de amenaza en el filtro, se aplica un filtro al DataFrame para mostrar solo las incidencias que coinciden con ese tipo. Si el usuario selecciona "Todos", no se aplica ningún filtro de tipo y se muestran todas las incidencias. Esto permite a los usuarios personalizar la visualización del historial de amenazas según sus intereses o necesidades específicas.
            df = df[df["Tipo"] == filtro_tipo]
        if filtro_riesgo != "Todos":
            df = df[df["Riesgo"] == filtro_riesgo]
        
        st.dataframe(df, use_container_width=True)
        
        # Estadísticas y Gráficos
        st.divider() #Se agrega un divisor visual para separar claramente la sección de estadísticas y gráficos del historial de amenazas, mejorando la organización visual de la interfaz y facilitando la navegación para los usuarios al distinguir entre la tabla de datos y las representaciones gráficas de las estadísticas.
        stats = gestor.get_estadisticas()
        
        if stats and stats["total"] > 0: #Si las estadísticas existen y el total de incidencias es mayor a 0, se procede a mostrar las métricas clave (total de incidencias, número de tipos y número de riesgos) y generar los gráficos de distribución por tipo y por riesgo. Si no hay incidencias registradas (total es 0), no se muestran las métricas ni los gráficos, evitando mostrar información vacía o irrelevante, lo que mejora la experiencia del usuario al proporcionar una interfaz más limpia y enfocada en los datos disponibles.
            c1, c2, c3 = st.columns(3)
            c1.metric("Total Incidencias", stats["total"])
            c2.metric("Nº de Tipos", len(stats["por_tipo"]))
            c3.metric("Nº de Riesgos", len(stats["por_riesgo"]))

            # Función para gráficos consistentes
            def crear_chart(data, x_field, y_field, titulo, color_range=None): #Esta función auxiliar se encarga de crear un gráfico de barras utilizando Altair, tomando como argumentos el DataFrame de datos, los nombres de los campos para el eje x e y, el título del gráfico y un rango de colores opcional. Al centralizar la lógica de creación de gráficos en esta función, se asegura que todos los gráficos generados en la aplicación tengan un estilo consistente y se facilita la reutilización del código para crear diferentes gráficos con diferentes conjuntos de datos y configuraciones.
                base = alt.Chart(data).mark_bar(cornerRadiusTopLeft=8, cornerRadiusTopRight=8).encode(
                    x=alt.X(f"{x_field}:N", title=None, sort='-y'),
                    y=alt.Y(f"{y_field}:Q", title="Cantidad"),
                    color=alt.Color(f"{x_field}:N", scale=alt.Scale(range=color_range) if color_range else alt.Undefined, legend=None),
                    tooltip=[x_field, y_field]
                ).properties(height=300, title=titulo)
                return base

            col_g1, col_g2 = st.columns(2)
            
            with col_g1:
                if "por_riesgo" in stats:
                    r_df = pd.DataFrame(list(stats["por_riesgo"].items()), columns=["Riesgo", "Cant"]) #Se crea un DataFrame a partir de las estadísticas de distribución por riesgo, convirtiendo el diccionario de riesgos en una lista de tuplas y luego en un DataFrame con columnas "Riesgo" y "Cant". Esto facilita la generación del gráfico de barras que muestra la distribución de incidencias por nivel de riesgo, proporcionando una representación visual clara y fácil de interpretar de cómo se distribuyen las amenazas según su nivel de riesgo.
                    st.altair_chart(crear_chart(r_df, "Riesgo", "Cant", "Distribución por Riesgo", ["#1f77b4", "#ff7f0e", "#d62728", "#7f7f7f"]), use_container_width=True) #Se genera un gráfico de barras utilizando Altair para mostrar la distribución de incidencias por nivel de riesgo, utilizando un rango de colores específico para cada nivel de riesgo (BAJO, MEDIO, ALTO, CRITICO) para mejorar la visualización y facilitar la interpretación de los datos. El gráfico se muestra en la interfaz de Streamlit con el título "Distribución por Riesgo" y se ajusta al ancho del contenedor para una mejor presentación.

            with col_g2:
                if "por_tipo" in stats:
                    t_data = [{"Tipo": tipo_traduccion.get(k, k), "Cant": v} for k, v in stats["por_tipo"].items()] #Se crea una lista de diccionarios a partir de las estadísticas de distribución por tipo, traduciendo las claves usando el diccionario de traducción y manteniendo los valores originales. Esto facilita la generación del gráfico de barras que muestra la distribución de incidencias por tipo, proporcionando una representación visual clara y fácil de interpretar de cómo se distribuyen las amenazas según su tipo.
                    t_df = pd.DataFrame(t_data)
                    st.altair_chart(crear_chart(t_df, "Tipo", "Cant", "Distribución por Tipo"), use_container_width=True) #Se genera un gráfico de barras utilizando Altair para mostrar la distribución de incidencias por tipo, utilizando un rango de colores específico para cada tipo de amenaza. El gráfico se muestra en la interfaz de Streamlit con el título "Distribución por Tipo" y se ajusta al ancho del contenedor para una mejor presentación.
    else:
        st.info("💡 No hay incidencias registradas aún. Use el panel lateral para añadir la primera.")

    # Acciones extra en Sidebar
    st.sidebar.markdown("---")
    st.sidebar.header("📂 Datos")
    if st.sidebar.button("⬇️ Exportar CSV"):
        gestor.guardar_csv()
        st.sidebar.success("CSV Actualizado")
    
    if st.sidebar.button("🔄 Recargar Datos"):
        gestor.cargar_desde_json()
        st.rerun()

if __name__ == "__main__": #Este bloque de código verifica si el script se está ejecutando directamente (en lugar de ser importado como un módulo) y, en ese caso, llama a la función main() para iniciar la aplicación de Streamlit. Esto es una práctica común en Python para asegurarse de que ciertas partes del código solo se ejecuten cuando el script se ejecute como programa principal, evitando que se ejecuten automáticamente al importar el módulo desde otro lugar.
    main()