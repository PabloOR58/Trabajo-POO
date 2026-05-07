import streamlit as st
import sys
import os
import pandas as pd

# Configuración de rutas para Mac
ruta_raiz = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../'))
if ruta_raiz not in sys.path:
    sys.path.insert(0, ruta_raiz)

# Importaciones del proyecto
try:
    from src.models.incidencia import (
        IncidenciaPhishing, IncidenciaMalware, IncidenciaFuerzaBruta,
        IncidenciaFugaDatos, IncidenciaAccesoNoAutorizado
    )
    from src.controllers.gestor_datos import GestorIncidencias
    from src.utils.excepciones import ValidacionException, GestorDatosException
except ImportError as e:
    st.error(f"Error de importación: {e}")

def main():
    st.set_page_config(page_title="Ciberseguridad UE", layout="wide")
    st.title("🛡️ Sistema de Análisis de Ciberseguridad")
    st.write("Grado en Inteligencia Artificial - Universidad Europea")

    # Inicializar gestor y cargar datos
    gestor = GestorIncidencias()
    gestor.cargar_desde_json()  # Cargar desde JSON si existe

    # Sidebar para registro
    st.sidebar.header("Nueva Incidencia")
    with st.sidebar.form("form_registro"):
        id_inc = st.text_input("ID de Incidencia")
        titulo = st.text_input("Título")
        descripcion = st.text_area("Descripción")
        fecha = st.date_input("Fecha").strftime("%Y-%m-%d")
        afectados = st.number_input("Nº de afectados", min_value=0, step=1)
        tipo = st.selectbox("Tipo", ["Phishing", "Malware", "Fuerza Bruta", "Fuga de Datos", "Acceso No Autorizado"])
        
        # Campos específicos según tipo
        if tipo == "Phishing":
            url_maliciosa = st.text_input("URL Maliciosa")
            emails_afectados = st.number_input("Emails Afectados", min_value=0, step=1)
        elif tipo == "Malware":
            tipo_malware = st.text_input("Tipo de Malware")
            sistemas_afectados = st.number_input("Sistemas Afectados", min_value=0, step=1)
        elif tipo == "Fuerza Bruta":
            intentos = st.number_input("Intentos", min_value=0, step=1)
            ip_origen = st.text_input("IP Origen")
        elif tipo == "Fuga de Datos":
            registros_expuestos = st.number_input("Registros Expuestos", min_value=0, step=1)
            datos_sensibles = st.checkbox("Datos Sensibles")
        elif tipo == "Acceso No Autorizado":
            usuario = st.text_input("Usuario")
            recurso_accedido = st.text_input("Recurso Accedido")
        
        submit = st.form_submit_button("Registrar")

        if submit:
            try:
                # Validaciones
                if not id_inc or not titulo or not descripcion:
                    raise ValidacionException("Campos obligatorios: ID, Título, Descripción")
                if afectados < 0:
                    raise ValidacionException("Número de afectados debe ser positivo")
                
                # Crear instancia según tipo
                if tipo == "Phishing":
                    if not url_maliciosa:
                        raise ValidacionException("URL maliciosa requerida")
                    nueva = IncidenciaPhishing(id_inc, titulo, descripcion, fecha, afectados, url_maliciosa, emails_afectados)
                elif tipo == "Malware":
                    if not tipo_malware:
                        raise ValidacionException("Tipo de malware requerido")
                    nueva = IncidenciaMalware(id_inc, titulo, descripcion, fecha, afectados, tipo_malware, sistemas_afectados)
                elif tipo == "Fuerza Bruta":
                    if not ip_origen:
                        raise ValidacionException("IP origen requerida")
                    nueva = IncidenciaFuerzaBruta(id_inc, titulo, descripcion, fecha, afectados, intentos, ip_origen)
                elif tipo == "Fuga de Datos":
                    nueva = IncidenciaFugaDatos(id_inc, titulo, descripcion, fecha, afectados, registros_expuestos, datos_sensibles)
                elif tipo == "Acceso No Autorizado":
                    if not usuario or not recurso_accedido:
                        raise ValidacionException("Usuario y recurso requeridos")
                    nueva = IncidenciaAccesoNoAutorizado(id_inc, titulo, descripcion, fecha, afectados, usuario, recurso_accedido)
                
                gestor.registrar(nueva)
                gestor.guardar_json()
                st.sidebar.success("Incidencia registrada con éxito")
                st.rerun()  # Recargar la página
            except (ValidacionException, GestorDatosException) as e:
                st.sidebar.error(f"⚠️ {e}")

    # Filtros
    st.header("📊 Historial de Amenazas")
    col1, col2 = st.columns(2)
    with col1:
        filtro_tipo = st.selectbox("Filtrar por Tipo", ["Todos"] + ["Phishing", "Malware", "Fuerza Bruta", "Fuga de Datos", "Acceso No Autorizado"])
    with col2:
        filtro_riesgo = st.selectbox("Filtrar por Riesgo", ["Todos", "ALTO", "MEDIO", "CRITICO"])

    # Obtener DataFrame
    df = gestor.to_dataframe()
    if not df.empty:
        # Aplicar filtros
        if filtro_tipo != "Todos":
            df = df[df["Tipo"] == filtro_tipo]
        if filtro_riesgo != "Todos":
            df = df[df["Riesgo"] == filtro_riesgo]
        
        st.dataframe(df, use_container_width=True)
        
        # Estadísticas
        st.subheader("Estadísticas")
        stats = gestor.get_estadisticas()
        if stats:
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Incidencias", stats["total"])
            with col2:
                st.metric("Tipos Únicos", len(stats["por_tipo"]))
            with col3:
                st.metric("Riesgos Únicos", len(stats["por_riesgo"]))
            
            # Gráficos
            st.subheader("Distribución por Riesgo")
            if "por_riesgo" in stats:
                riesgo_df = pd.DataFrame(list(stats["por_riesgo"].items()), columns=["Riesgo", "Cantidad"])
                st.bar_chart(riesgo_df.set_index("Riesgo"))
            
            st.subheader("Distribución por Tipo")
            if "por_tipo" in stats:
                tipo_df = pd.DataFrame(list(stats["por_tipo"].items()), columns=["Tipo", "Cantidad"])
                st.bar_chart(tipo_df.set_index("Tipo"))
    else:
        st.info("No hay incidencias registradas.")

    # Botones para guardar/cargar
    st.sidebar.header("Acciones")
    if st.sidebar.button("Guardar en CSV"):
        ruta = gestor.guardar_csv()
        st.sidebar.success(f"Guardado en {ruta}")
    if st.sidebar.button("Guardar en JSON"):
        ruta = gestor.guardar_json()
        st.sidebar.success(f"Guardado en {ruta}")
    if st.sidebar.button("Cargar desde JSON"):
        gestor.cargar_desde_json()
        st.sidebar.success("Cargado desde JSON")
        st.rerun()

if __name__ == "__main__":
    main()