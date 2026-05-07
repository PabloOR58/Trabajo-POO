import sys
import os

# [span_0](start_span)Esto es vital en Mac para que encuentre la carpeta raíz del proyecto[span_0](end_span)
ruta_raiz = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../'))
if ruta_raiz not in sys.path:
    sys.path.append(ruta_raiz)

try:
    from src.models.incidencia import IncidenciaPhishing, IncidenciaMalware
    from src.controllers.gestor_datos import GestorIncidencias
    from src.utils.excepciones import ValidacionException
except ImportError as e:
    print(f"Error importando: {e}")