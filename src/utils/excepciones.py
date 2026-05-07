class ValidacionException(Exception):
    """Error de validación de datos."""

    def __init__(self, mensaje):
        self.mensaje = mensaje
        super().__init__(self.mensaje)


class GestorDatosException(Exception):
    """Error general del gestor de datos."""

    def __init__(self, mensaje):
        self.mensaje = mensaje
        super().__init__(self.mensaje)
