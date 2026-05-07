#!/usr/bin/env python3
"""
Punto de entrada principal para la aplicación de ciberseguridad.
Ejecuta la interfaz de Streamlit.
"""

import sys
import os

# Agregar la ruta raíz al path
ruta_raiz = os.path.dirname(os.path.abspath(__file__))
if ruta_raiz not in sys.path:
    sys.path.insert(0, ruta_raiz)

from src.views.interfaz import main

if __name__ == "__main__":
    main()