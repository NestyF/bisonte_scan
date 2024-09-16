# Bisonte - Herramienta de Escaneo de Vulnerabilidades

**Bisonte** es una herramienta avanzada para escanear y evaluar vulnerabilidades en dominios y direcciones IP. Utiliza la API de Shodan para obtener información de puertos y vulnerabilidades, y la API de Vulners para obtener detalles adicionales sobre las vulnerabilidades.

## Descripción

Bisonte proporciona funcionalidades para:
- Obtener registros DNS de un dominio.
- Escanear puertos de direcciones IP detectadas.
- Revisar vulnerabilidades asociadas a estas IPs usando Shodan y Vulners.

## Requisitos

1. **API de Shodan**: Necesitarás una clave API de Shodan para acceder a la información de puertos y vulnerabilidades. Puedes obtener una clave API registrándote en [Shodan](https://shodan.io/).

2. **API de Vulners**: Necesitarás una clave API de Vulners para obtener detalles adicionales sobre las vulnerabilidades. Puedes obtener una clave API registrándote en [Vulners](https://vulners.com/).

3. **Dependencias**:
    - `requests`
    - `rich`
    - `art`

    Puedes instalar las dependencias con:

    ```bash
    pip install requests rich art
    ```

## Instalación

1. **Clona el repositorio**:

    ```bash
    git clone https://github.com/tu-usuario/bisonte.git
    ```

2. **Cambia al directorio del proyecto**:

    ```bash
    cd bisonte
    ```

3. **Instala las dependencias**:

    Asegúrate de tener `pip` instalado, luego ejecuta:

    ```bash
    pip install -r requirements.txt
    ```

4. **Configura las claves API**:

    Asegúrate de reemplazar las claves API en el archivo de código (`bisonte.py`) con tus propias claves de Shodan y Vulners.

## Uso

1. Ejecuta el script principal:

    ```bash
    python bisonte.py
    ```

2. Introduce el dominio principal cuando se te solicite.

3. El script mostrará el banner, procesará los registros DNS, y te preguntará si deseas revisar las vulnerabilidades de las IPs detectadas.

## Imágenes

![image](https://github.com/user-attachments/assets/101f8451-488a-4ad8-b60d-e7b3f6927415)

![image](https://github.com/user-attachments/assets/3dafcf8e-c975-417a-90f7-27379c4e2c0f)

![image](https://github.com/user-attachments/assets/bbdd0954-4c5f-4be9-ada5-3c68d9134f13)

![image](https://github.com/user-attachments/assets/fd807e77-871c-47fc-8676-f96d13133036)

## Licencia

Este proyecto está licenciado bajo la Licencia MIT - consulta el archivo [LICENSE](LICENSE) para obtener más detalles.

¡Gracias por tu interés en Bisonte!
