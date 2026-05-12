class ValidacionException(Exception): 
    """Error de validación de datos."""

    def __init__(self, mensaje): #Este constructor de la clase ValidacionException recibe un mensaje como argumento, lo asigna a un atributo de instancia llamado mensaje y luego llama al constructor de la clase base Exception para inicializar la excepción con ese mensaje. Esto permite que cuando se lance una ValidacionException, se pueda proporcionar un mensaje descriptivo que explique el motivo del error de validación, facilitando la depuración y el manejo de errores en el programa.
        self.mensaje = mensaje
        super().__init__(self.mensaje)


class GestorDatosException(Exception):
    """Error general del gestor de datos."""

    def __init__(self, mensaje):
        self.mensaje = mensaje
        super().__init__(self.mensaje)
