#!/usr/bin/env python3
"""
Punto de entrada principal para la aplicación de ciberseguridad.
Ejecuta la interfaz de Streamlit.
"""

import sys
import os

# Agregar la ruta raíz al path
ruta_raiz = os.path.dirname(os.path.abspath(__file__)) #Se obtiene la ruta absoluta del directorio donde se encuentra el archivo main.py y se asigna a la variable ruta_raiz. Esto es útil para asegurarse de que las importaciones de módulos dentro del proyecto funcionen correctamente, independientemente de dónde se ejecute el script, ya que agrega la ruta raíz del proyecto al sistema de rutas de Python.
if ruta_raiz not in sys.path:
    sys.path.insert(0, ruta_raiz)

from src.views.interfaz import main #Se importa la función main desde el módulo src.views.interfaz, que es el punto de entrada para la interfaz de usuario de la aplicación. Esta función se encargará de iniciar la aplicación de Streamlit y mostrar la interfaz al usuario.

if __name__ == "__main__":
    main()