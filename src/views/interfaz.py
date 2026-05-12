import streamlit as st
import sys
import os
import pandas as pd
import altair as alt

# Configuración de rutas para Mac/Linux/Windows
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
    st.error(f"Error de importación crítico: {e}")
    st.stop()

def main():
    st.set_page_config(page_title="Ciberseguridad UE", layout="wide")
    st.title("Sistema de Análisis de Ciberseguridad")
    st.write("Grado en Inteligencia Artificial - Universidad Europea")

    # Inicializar gestor y cargar datos
    gestor = GestorIncidencias()
    ruta_json = os.path.join(ruta_raiz, "data", "incidencias.json")
    if os.path.exists(ruta_json):
        gestor.cargar_desde_json()

    # =========================================================
    # SIDEBAR: REGISTRO DE INCIDENCIAS
    # =========================================================
    st.sidebar.header("📝 Nueva Incidencia")
    
    # IMPORTANTE: El selector de tipo va FUERA del form para que la interfaz cambie al elegir
    tipo_seleccionado = st.sidebar.selectbox(
        "Seleccione Tipo de Amenaza", 
        ["Phishing", "Malware", "Fuerza Bruta", "Fuga de Datos", "Acceso No Autorizado"]
    )

    with st.sidebar.form("form_registro", clear_on_submit=True):
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

        if submit:
            try:
                # Validaciones básicas comunes
                if not id_inc or not titulo or not descripcion:
                    raise ValidacionException("Faltan campos obligatorios (ID, Título o Descripción)")
                
                fecha_str = fecha_dt.strftime("%Y-%m-%d")
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
            except (ValidacionException, GestorDatosException) as e:
                st.sidebar.error(f"{e}")

    # =========================================================
    # CUERPO PRINCIPAL: VISUALIZACIÓN
    # =========================================================
    st.header("Historial de Amenazas")
    
    df = gestor.to_dataframe()
    
    if not df.empty:
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
        col_f1, col_f2 = st.columns(2)
        with col_f1:
            filtro_tipo = st.selectbox("Filtrar por Tipo", ["Todos"] + list(tipo_traduccion.values()))
        with col_f2:
            filtro_riesgo = st.selectbox("Filtrar por Riesgo", ["Todos", "BAJO", "MEDIO", "ALTO", "CRITICO"])

        # Aplicar filtros al DataFrame
        if filtro_tipo != "Todos":
            df = df[df["Tipo"] == filtro_tipo]
        if filtro_riesgo != "Todos":
            df = df[df["Riesgo"] == filtro_riesgo]
        
        st.dataframe(df, use_container_width=True)
        
        # Estadísticas y Gráficos
        st.divider()
        stats = gestor.get_estadisticas()
        
        if stats and stats["total"] > 0:
            c1, c2, c3 = st.columns(3)
            c1.metric("Total Incidencias", stats["total"])
            c2.metric("Nº de Tipos", len(stats["por_tipo"]))
            c3.metric("Nº de Riesgos", len(stats["por_riesgo"]))

            # Función para gráficos consistentes
            def crear_chart(data, x_field, y_field, titulo, color_range=None):
                base = alt.Chart(data).mark_bar(cornerRadiusTopLeft=8, cornerRadiusTopRight=8).encode(
                    #N significa que es texto
                    x=alt.X(f"{x_field}:N", title=None, sort='-y'),
                    # sort = -y ordena de mayor a menor las categorías en el eje x según la cantidad (y)
                    y=alt.Y(f"{y_field}:Q", title="Cantidad"),
                    #Color dependiente del tipo o riesgo, con rango personalizado si se da, o colores por defecto si no
                    color=alt.Color(f"{x_field}:N", scale=alt.Scale(range=color_range) if color_range else alt.Undefined, legend=None),
                    tooltip=[x_field, y_field]
                ).properties(height=300, title=titulo)
                return base

            col_g1, col_g2 = st.columns(2)
            
            with col_g1:
                if "por_riesgo" in stats:
                    r_df = pd.DataFrame(list(stats["por_riesgo"].items()), columns=["Riesgo", "Cant"])
                    st.altair_chart(crear_chart(r_df, "Riesgo", "Cant", "Distribución por Riesgo", ["#1f77b4", "#ff7f0e", "#d62728", "#7f7f7f"]), use_container_width=True)

            with col_g2:
                if "por_tipo" in stats:
                     #Si existe traudccion de riesgo, la aplica, sino deja el riesgo original
                    t_data = [{"Tipo": tipo_traduccion.get(k, k), "Cant": v} for k, v in stats["por_tipo"].items()]
                    t_df = pd.DataFrame(t_data)
                    st.altair_chart(crear_chart(t_df, "Tipo", "Cant", "Distribución por Tipo"), use_container_width=True)
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

if __name__ == "__main__":
    main()