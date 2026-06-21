# Packet Sniffer - Redes

Proyecto final para la materia de Redes. Este es un sniffer de paquetes escrito en C++ que captura tráfico de red en tiempo real y muestra los datos en una interfaz gráfica interactiva.

## Requisitos Previos
- **Sistema Operativo**: Windows
- **Compilador**: MinGW (`g++` compatible con C++17)
- **Npcap**: Necesitas instalar [Npcap](https://npcap.com/) en tu computadora para que el programa pueda leer las tarjetas de red físicas.

## Librerías Utilizadas
- **Npcap (Libpcap para Windows)**: El motor principal que atrapa los paquetes físicos.
- **Dear ImGui**: Librería súper ligera para crear la interfaz gráfica.
- **GLFW y OpenGL3**: Herramientas necesarias para poder renderizar la ventana de ImGui y los gráficos.

## Cómo Compilar
Abre tu consola de comandos en la carpeta raíz del proyecto y ejecuta la siguiente línea de compilación (enlaza todas las librerías gráficas y de red en un solo archivo ejecutable):

```bash
g++ -g -std=c++17 main.cpp imgui/imgui.cpp imgui/imgui_demo.cpp imgui/imgui_draw.cpp imgui/imgui_tables.cpp imgui/imgui_widgets.cpp imgui/backends/imgui_impl_glfw.cpp imgui/backends/imgui_impl_opengl3.cpp -o build/sniffer.exe -InpcapSDK/Include -Iimgui -Iimgui/backends -Iglfw/include -LnpcapSDK/Lib/x64 -Lglfw/lib-mingw-w64 -lwpcap -lPacket -lws2_32 -lglfw3 -lopengl32 -lgdi32 -static -static-libgcc -static-libstdc++ -DWPCAP -DHAVE_REMOTE
```

## Cómo Ejecutar
Una vez que compile sin errores, el ejecutable estará en la carpeta `build/sniffer.exe`. 
**IMPORTANTE:** Tienes que correr el programa como **Administrador**. Si no eres administrador, Npcap te va a rechazar el permiso para "escuchar" la tarjeta de red y el sniffer no atrapará tráfico.
