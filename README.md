# Sistema de Análisis de Ciberseguridad

Aplicación desarrollada en Python con Streamlit para el registro, clasificación y análisis de incidencias de ciberseguridad, aplicando principios de Programación Orientada a Objetos.

## Funcionalidades

- **Registro de Incidencias**: Permite registrar diferentes tipos de incidencias (Phishing, Malware, Fuerza Bruta, Fuga de Datos, Acceso No Autorizado).
- **Clasificación por Riesgo**: Cada incidencia calcula automáticamente su nivel de riesgo (Bajo, Medio, Alto, Crítico).
- **Recomendaciones**: Proporciona recomendaciones específicas según el tipo de incidencia.
- **Filtros**: Filtrar incidencias por tipo o nivel de riesgo.
- **Estadísticas Visuales**: Gráficos de barras para distribución por riesgo y tipo.
- **Persistencia**: Guardar y cargar datos en formato CSV o JSON.
- **Validación Avanzada**: Excepciones personalizadas para validar datos de entrada.

## Arquitectura

- **Modelo MVC**: Separación clara en modelos (incidencias), controladores (gestor de datos) y vistas (interfaz Streamlit).
- **Herencia y Polimorfismo**: Clase abstracta `Incidencia` con subclases especializadas.
- **Excepciones Personalizadas**: `ValidacionException` y `GestorDatosException`.

## Requisitos

- Python 3.8+
- Streamlit
- Pandas

## Instalación

1. Clonar el repositorio:
   ```bash
   git clone <url>
   cd Trabajo-POO
   ```

2. Instalar dependencias:
   ```bash
   pip install streamlit pandas
   ```

## Ejecución

Ejecutar la aplicación:
```bash
python main.py
```

O directamente:
```bash
streamlit run src/views/interfaz.py
```

La aplicación estará disponible en `http://localhost:8501`.

## Estructura del Proyecto

```
Trabajo-POO/
├── main.py                 # Punto de entrada
├── README.md               # Documentación
├── data/
│   ├── incidencias.json    # Datos en JSON
│   └── incidencias.csv     # Datos en CSV
└── src/
    ├── __init__.py
    ├── controllers/
    │   ├── __init__.py
    │   └── gestor_datos.py # Lógica de negocio
    ├── models/
    │   ├── __init__.py
    │   └── incidencia.py   # Modelos de datos
    ├── utils/
    │   ├── __init__.py
    │   └── excepciones.py  # Excepciones personalizadas
    └── views/
        ├── __init__.py
        └── interfaz.py     # Interfaz de usuario
```

## Diagrama UML

### Clases

- **Incidencia** (Abstract)
  - Atributos: id, titulo, descripcion, fecha, afectados
  - Métodos abstractos: calcular_riesgo(), get_recomendaciones()

- **IncidenciaPhishing** (hereda de Incidencia)
  - Atributos adicionales: url_maliciosa, emails_afectados

- **IncidenciaMalware** (hereda de Incidencia)
  - Atributos adicionales: tipo_malware, sistemas_afectados

- **IncidenciaFuerzaBruta** (hereda de Incidencia)
  - Atributos adicionales: intentos, ip_origen

- **IncidenciaFugaDatos** (hereda de Incidencia)
  - Atributos adicionales: registros_expuestos, datos_sensibles

- **IncidenciaAccesoNoAutorizado** (hereda de Incidencia)
  - Atributos adicionales: usuario, recurso_accedido

- **GestorIncidencias**
  - Métodos: registrar(), listar(), buscar_por_id(), filtrar_por_tipo(), filtrar_por_riesgo(), etc.

- **Excepciones**
  - ValidacionException
  - GestorDatosException

## Herramientas Empleadas

- **Python**: Lenguaje de programación.
- **Streamlit**: Framework para interfaces web.
- **Pandas**: Manipulación de datos.
- **JSON/CSV**: Formatos de persistencia.

## Consultas y Resultados

- La aplicación valida automáticamente los datos de entrada.
- Las estadísticas se calculan en tiempo real.
- Los filtros permiten una navegación eficiente de los datos.

## Bibliografía

- Documentación oficial de Python: https://docs.python.org/3/
- Streamlit documentation: https://docs.streamlit.io/
- Pandas documentation: https://pandas.pydata.org/docs/


streamlit run src/views/interfaz.py
