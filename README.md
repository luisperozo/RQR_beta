# RQR-Ollama

RQR-Ollama es una herramienta de automatización de redes que integra modelos de lenguaje de [Ollama](https://ollama.com/) para interactuar con dispositivos y generar diagramas de topología.

## Características
- Prueba de conectividad y recopilación de vecinos CDP mediante **Netmiko**.
- Generación de topologías de red y diagramas con **NetworkX** y **Matplotlib**.
- Verificación de configuración y gestión de inventario de dispositivos.
- Interfaz web para chatear con el modelo.

## Instalación
1. Clona el repositorio:
   ```bash
   git clone https://github.com/<usuario>/RQR_beta.git
   cd RQR_beta
   ```
2. Crea un entorno virtual (opcional) e instala las dependencias:
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

## Uso
### Chat de automatización
Ejecuta la interfaz de consola para interactuar con los dispositivos:
```bash
python RQR_chat.py
```

### Chat web
La interfaz web reutiliza la lógica de `RQR_chat.py` para ofrecer las mismas capacidades de automatización.
Inicia el servidor y accede desde tu navegador:
```bash
python web_ui.py
```

## Variables de entorno
- `SSH_USERNAME`, `SSH_PASSWORD`, `SSH_SECRET`: Credenciales para los dispositivos de red.
- `OLLAMA_MODEL`: Nombre del modelo a usar (por defecto `llama3.1`).
- `PORT`: Puerto para la interfaz web (por defecto `8000`).
