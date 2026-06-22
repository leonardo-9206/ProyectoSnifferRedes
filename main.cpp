// Proyecto Final: Packet Sniffer
// Equipo: Erich Leonardo, Diego Joao, Joshua Alejandro, Rodrigo Vazquez, Carlos Antonio
// Descripcion: Sniffer desarrollado en C++ utilizando Npcap para la captura de paquetes y Dear ImGui para la interfaz grafica.
// Arquitectura: Separamos el hilo grafico del hilo de captura de red para evitar que la app se congele.
#include <pcap.h>
#include <winsock2.h>
#include <thread>
#include <mutex>
#include <atomic>
#include <vector>
#include <string>
#include <fstream>
#include <cstdio>
#include <cstring>

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>

using namespace std;

//Estructuras para las cabeceras de los protocolos de red (importante quitar el padding con pragma pack)
#pragma pack(push, 1)   //Esto es para deshacernos de los espacios que hay entre bytes, para q los datos concuerden con nuestras estructuras
struct ip_address { u_char b1, b2, b3, b4; };   //los 4 octetos de cada ip

struct ip_header {
    u_char  ver_ihl, tos;   //combina la version de ip y el IHL (internet header lenght- nos dice q tan larga es la cabecera)
    //tos (type of service) se usa para dar prioridades (ej. voz sobre datos)
    u_short tlen, id, flags_fo; //tlen (total lenght) tamaño tot del paquete - 65,535 bytes, id-para identificar el paquete en caso de que ocurra
    //fragmentacion, flags_fo-dice si hubo fragmentacion y en que orden deben rearmarse
    u_char  ttl, proto; //ttl (time to live) - contador de "vidas", cada q el paquete pasa por el router se le resta 1, si llega a 0 muere
    //proto - protocolo, nos indica que protocolo sigue, si vale 6 -> TCP, si es 17, la siguiente capa es UDP
    u_short crc;    //checksum - calculo matematico para verificar que la cabecera no se corrompio en el viaje
    ip_address saddr, daddr;    //direcciones de origen y destino
};

struct udp_header { u_short sport, dport, len, crc; }; 
//contiene los puertos de origen y destino (cada puerto ocupa 2 bytes), len - longitud total del mensaje UDP, crc - misma comprobacion

struct tcp_header {
    u_short sport, dport;   //puertos de origen y destino
    u_int   seq, ack;   //seq (Sequence number) y ack (acknowledgment number) - seq, sirve para identificar a q parte del archivo pertenece esa parte
    //ack nos dice que es lo q ya le llego, si no manda mensaje entonces se perdio esa parte
    u_char  data_offset, flags; //data-offset indica donde termina conf. de TCP y donde comienzan los datos reales (payload)
    //flags - banderas de TCP, indican el estado de conexión
    u_short window, crc, urp;   //window - tamaño de ventana, crc - checksum
    //urp - (urgent pointer) sirve para informar cuales datos deben procesarse inmediatamente
};
#pragma pack(pop)   //devolvemos los datos pero ahora sin padding

//ESTRUCTURAS DE DATOS PARA MANEJAR INFO CAPTURADA
//Metadatos livianos del paquete (para mostrarlos rapido en la tabla sin saturar la memoria)
struct PaqueteMeta {    //guarda la info dentro de este objeto
    string ip_origen, ip_destino, protocolo, servicio;
    int puerto_origen = 0;
    int puerto_destino = 0;
    size_t raw_size = 0;
};

//Variables globales (usamos mutex porque la interfaz grafica y el sniffer corren al mismo tiempo)
static vector<PaqueteMeta> g_meta;   //metadatos para la tabla, cada posicion representa un paquete
static vector<vector<uint8_t>> g_raw;  //bytes crudos por paquete, cada posicion tiene la info del paquete en hexadecimal
static mutex g_mtx; //Candado para los dos hilos
static atomic<bool> g_capturando{false};    //Bandera, si es true = capturando, si es false = detenido
//usamos atomic pq hay varios hilos (la gui y el packet_handler)
static pcap_t* g_handle = nullptr;      //conexion abierta con Npcap, nos permite q el programa <-> Npcap <-> tarjeta de red

//Toma la estructura ip_adress y la formatea en una cadena de texto -> 192.168.1.1
static string ipStr(ip_address ip) {
    char buf[20];
    snprintf(buf, sizeof(buf), "%d.%d.%d.%d", ip.b1, ip.b2, ip.b3, ip.b4);
    return buf;
}
//Recibe un numero de puerto y devuelve el nombre correspondiente
static const char* getServicio(int puerto) {
    switch (puerto) {
        case 20: return "FTP-Data";
        case 21: return "FTP";
        case 22: return "SSH";
        case 23: return "Telnet";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 67: return "DHCP-S";
        case 68: return "DHCP-C";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 123: return "NTP";
        case 143: return "IMAP";
        case 443: return "HTTPS";
        case 445: return "SMB";
        case 587: return "SMTP-S";
        case 993: return "IMAPS";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 5432: return "Postgres";
        default: return "---";
    }
}

//Callback de captura: Esta funcion la manda a llamar npcap automaticamente cada que atrapa un paquete
void packet_handler(u_char*, const struct pcap_pkthdr* hdr, const u_char* pkt) {
    if (hdr->caplen < 14){
        return; //si la cabecera Ethernet mide menos de 14 bytes entonces se descarta
    }

    auto* ih = (ip_header*)(pkt + 14);  //obtener la cabecera IP, sumamos 14 bytes al puntero para brincar a la cabecera Ethernet
    if ((ih->ver_ihl >> 4) != 4){   //Si no es IPV4 entonces no nos importa
        return; //solo IPv4
    }
    PaqueteMeta meta;
    meta.ip_origen  = ipStr(ih->saddr);
    meta.ip_destino = ipStr(ih->daddr);
    meta.raw_size   = hdr->caplen;

    u_int ihl = (ih->ver_ihl & 0xf)*4;    //la cabecera no siempre mide lo mismo, por eso calculamos ihl para saber donde comienza TCP o UDP

    if (ih->proto == 6 && hdr->caplen >= 14u + ihl + 20u) { /*calculamos la posicion de la cabecera TCP basandonos en el tamaño variable 
        de la cabecera IP(ihl)*/
        meta.protocolo = "TCP";
        auto* th = (tcp_header*)((u_char*)ih + ihl);    //salta toda la cabecera IP
        //ntohs -> newtwork to host short
        meta.puerto_origen  = ntohs(th->sport); //Leemos los puertos de origen y destino
        meta.puerto_destino = ntohs(th->dport); //ntohs -> Los routers ordenan todo en Big Endian (byte grande primero)
        //las computadoras en Little Endian, asi que ntohs traduce el orden de los bytes para que el num de puerto sea correcto
    } else if (ih->proto == 17 && hdr->caplen >= 14u + ihl + 8u) {  /*Hacemos lo mismo con la cabecera UDP*/
        meta.protocolo = "UDP";
        auto* uh = (udp_header*)((u_char*)ih + ihl);
        meta.puerto_origen  = ntohs(uh->sport);
        meta.puerto_destino = ntohs(uh->dport);
    } else if (ih->proto == 1) {    //Si no es UDP o TCP entonces es alguno de los otros protocolos
        meta.protocolo = "ICMP";
    } else if (ih->proto == 2) {
        meta.protocolo = "IGMP";
    } else if (ih->proto == 41) {
        meta.protocolo = "IPv6";
    } else if (ih->proto == 89) {
        meta.protocolo = "OSPF";
    } else {
        char buf[24];
        snprintf(buf, sizeof(buf), "Proto(%d)", ih->proto);
        meta.protocolo = buf;
    }

    const char* svc = getServicio(meta.puerto_destino);
    if (string(svc) == "---"){
        svc = getServicio(meta.puerto_origen);
    }
    meta.servicio = svc;    //le coloca su servicio correspondiente

    vector<uint8_t> raw(pkt, pkt + hdr->caplen);    //copia TODOS los bytes de los paquetes, nos sirve para la zona RAW de la GUI

    lock_guard<mutex> lk(g_mtx);    //abrimos el cerrojo g_mtx
    g_meta.push_back(move(meta));   //agregamos el paquete procesado
    g_raw.push_back(move(raw));     //sus bytes crudos (hex) a la memoria global
}

//Este es el hilo secundario, abre la tarjeta de red y empieza el ciclo de captura (pcap_loop)
void runCapture(string iface, string filtro) {
    //iface - nombre de la interfaz de red (Ethernet, Wifi, Intel(R))
    //filtr - el filtro que escribio el usuario
    char errbuf[PCAP_ERRBUF_SIZE];  //se reserva memoria para mensajes de errores (256 de memoria)
    g_handle = pcap_open_live(iface.c_str(), 65536, 1, 1000, errbuf); //abrimos la tarjeta de red
    //pcap_open_live(const char*, snaplen -> cuantos bytes maximos capturar?, 1 - promiscuos mode (capturar todo), 1000 (timeout ms), errores)
    if (!g_handle) {    //fallo la apertura?
        g_capturando = false;   //no se capturo el paquete
        return;     //salimos de la funcion
    }

    if (!filtro.empty()) {  //tenemos un filtro?
        struct bpf_program fp;  //creamos una estructura bpf (Berkeley Packet Filter) para guardar el filtro compilada
        if (pcap_compile(g_handle, &fp, filtro.c_str(), 1, PCAP_NETMASK_UNKNOWN) == 0) { //aplicamos el filtro (si es que hay uno) == 0 -> comp exitosa
            //g_handle interfaz donde se aplicara, direccion donde guardar el filtro compilado, texto del filtro, optimizacion, mascara de red desconocida
            pcap_setfilter(g_handle, &fp);  //ahora Npcap sabe que paquetes dejar pasar
            pcap_freecode(&fp); //ya no se necesita la ver compilada, evitamos fugas de memoria
        }
    }

    pcap_loop(g_handle, 0, packet_handler, nullptr);    //comienza captura, el sniffer
    //interfaz abierta, cantidad de paquetes/0 ->capturar indefinidamente, callback, dato extra (contexto)
    pcap_close(g_handle);   //liberamos tarjeta, buffers y memoria inter. de Npcap
    g_handle = nullptr;     //indicar que ya no hay interfaz abierta
    g_capturando = false;   //la captura termino
}

//Funcion para formatear los bytes crudos a una vista hexadecimal clasica, es static para q no se destruya luego luego
static void renderHex(const vector<uint8_t>& data) {    //recibimos el paquete completo de bytes
    if (data.empty()) { ImGui::TextDisabled("(sin datos)"); return; }
    //vector vacio? si es asi, muestra el mensaje
    static char buf[1024*128];  //buffer para construir texto, 1024*128 = 131072 bytes = 128KB
    int pos = 0;    //indica donde escribir en buf
    const int cap = (int)sizeof(buf) - 128; //capacidad maxima, cuanto espacio puede usar
    //Se le restan 128 para dejar espacio libre y evitar sobrepasar el arreglo
    for (size_t i = 0; i < data.size() && pos < cap; i += 16) { //recorremos el paquete, con lineas de 16 bytes
        pos += snprintf(buf + pos, cap - pos, "%04X  ", (unsigned)i); //imprime la direccion
        for (int j = 0; j < 16; j++) {  //recorre los 16 bytes de la linea
            if (i + j < data.size()){    //checar q no se salga del paquete
                pos += snprintf(buf + pos, cap - pos, "%02X ", data[i + j]);    //convertir decimal a hexadecimal
            } else{
                pos += snprintf(buf + pos, cap - pos, "   ");   //rellenar espacios para evitar "45 AA ?? ??"
            } if (j == 7){
                pos += snprintf(buf + pos, cap - pos, " "); //despues del byte 8 agrega un espacio
            }
        }

        pos += snprintf(buf + pos, cap - pos, "  ");    //separar hex del texto
        for (int j = 0; j < 16 && i + j < data.size(); j++) {   //convertir byte a caracteres
            uint8_t c = data[i + j];    //obtenemos dicho byte
            buf[pos++] = (c >= 32 && c < 127) ? (char)c : '.';  //caracteres imprimibles enter 32-127
            //si es letra muestrala, si no coloca un punto
        }
        buf[pos++] = '\n';
    }
    buf[pos] = '\0';    //termina el texto

    ImGui::InputTextMultiline("##hex", buf, sizeof(buf), ImVec2(800, 400), ImGuiInputTextFlags_ReadOnly);
    //Crear una caja de texto enorme de 800x400 y solo podemos copiar no modificar
}

//Funcion para guardar los datos de la tabla en un archivo Excel/CSV
static bool exportarCSV(const char* archivo) {
    ofstream f(archivo);    //crear el archivo
    if (!f) return false;   //si falla, no se pudo crear
    f << "Protocolo,Servicio,IP Origen,Puerto Origen,IP Destino,Puerto Destino,Bytes\n";    //escribir encabezados
    lock_guard<mutex> lk(g_mtx);    //mutex, mientras exportamos puede capturar mas paquetes asi que no lo permitimos
    for (size_t i = 0; i < g_meta.size(); i++) {    //recorrer paquete por paquete
        const auto& m = g_meta[i];  //cual paquete es
        f << m.protocolo << "," << m.servicio << "," << m.ip_origen << "," << m.puerto_origen << "," << m.ip_destino << "," << m.puerto_destino << "," << m.raw_size  << "\n";
        //escribimos en el archivo su protocolo, servicio, IP_origen, puerto_origen, etc.
    }
    return true;    //si se pudo crear el archivo
}

//Funcion auxiliar para darle colores bonitos a cada protocolo en la tabla
static ImVec4 colorProtocolo(const string& proto) {
    //usamos el formato RGB Alpha
    if (proto == "TCP"){
        return {0.40f, 0.80f, 1.00f, 1.0f};
    }
    if (proto == "UDP"){
        return {0.50f, 1.00f, 0.50f, 1.0f};
    }
    if (proto == "ICMP"){
        return {1.00f, 0.85f, 0.30f, 1.0f};
    }
    if (proto == "IGMP"){
        return {0.90f, 0.50f, 0.80f, 1.0f};
    }
    if (proto == "IPv6"){
        return {0.70f, 0.70f, 0.90f, 1.0f};
    }
    if (proto == "OSPF"){
        return {0.80f, 0.60f, 0.20f, 1.0f};
    }
    return {0.80f, 0.80f, 0.80f, 1.0f};
}

//Funcion principal que levanta la interfaz grafica y controla la aplicacion
int main() {
    //Inicializamos GLFW, libreria que crea ventanas
    if (!glfwInit()) return 1;  //si falla terminar el programa
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);  //OpenGL 3.3

    GLFWwindow* window = glfwCreateWindow(1400, 850, "Packet Sniffer - Redes", nullptr, nullptr);
    //crear ventana principal 1400 x 800
    if (!window) { glfwTerminate(); return 1; } //si no se pudo crear, liberar y terminar el programa

    glfwMakeContextCurrent(window); //le decimos a OpenGL q escriba dentro de esa ventana
    glfwSwapInterval(1);    //activar VSync, evitamos 300, 500 o 1000 FPS, son innecesarios

    //creamos el IMGUI
    IMGUI_CHECKVERSION();   //verificar la compatibilidad
    ImGui::CreateContext(); //crear contexto IMGUI, de lo contrario cosas como ImGui::Button() no funcionaran
    ImGuiIO& io = ImGui::GetIO();   //Obtener la configuracion interna
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;   //permitimos la navegacion con teclado
    ImGui::StyleColorsDark();   //tema oscuro :D

    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 4.0f;    //redondear ventanas
    style.FrameRounding = 3.0f;     //redondear botones
    style.ScrollbarRounding = 3.0f; //redondear la barra de scroll

    ImGui_ImplGlfw_InitForOpenGL(window, true); //Conectamos el ImGui con GLFW
    ImGui_ImplOpenGL3_Init("#version 330"); //Conectamos ImGui con OpenGL

    //Interfaces de red
    pcap_if_t* alldevs = nullptr;   //lista de adaptadores
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_findalldevs(&alldevs, errbuf); //Npcap bsuca Wifi, Ethernet, VPN, etc.

    vector<string> iface_names, iface_descs;    //guardar interfaces para pasar de \Device\ a Intel (R) Wi-Fi, por eso guardar ambas
    for (pcap_if_t* d = alldevs; d; d = d->next) {  //recorrer la lista enlazada
        iface_names.push_back(d->name);     //guardamos el nombre
        iface_descs.push_back(d->description ? d->description : d->name);   //guardar descripcion
    }
    pcap_freealldevs(alldevs);  //liberar memoria

    //Estado de la UI
    int sel_iface = 0;  //Interfaz seleccionada
    int sel_paquete = -1;   //Paquete seleccionado
    char filtro_buf[256] = "";  //Filtro BPF
    char csv_path[256] = "captura_trafico.csv";   //Nombre del csv

    bool show_welcome = true;   //Mostrar bienvenida
    bool auto_scroll = true;   //Scroll automatico

    //Cache del paquete seleccionado (evita lockear cada frame)
    PaqueteMeta cached_meta;    //Guarda el paquete seleccionado, con el, solo leemos una vez
    vector<uint8_t> cached_raw; 
    int cached_idx = -1;

    thread hilo_cap;    //donde se ejecuta runCapture(); si no, pcap_loop() bloquearia la interfaz
    bool exportado = false;

    //Estado para modal Hex
    bool open_hex_modal = false;
    vector<uint8_t> hex_raw_data;

    //Estado para modal Filtros
    bool open_filtros_modal = false;

    //loop del render, corazon de la GUI
    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();   //leer mouse y teclado
        ImGui_ImplOpenGL3_NewFrame();   //preparar OpenGL
        ImGui_ImplGlfw_NewFrame();  //preparar GLFW
        ImGui::NewFrame();  //Empieza un nuevo frame de ImGui

        if (show_welcome) { //pantalla de bienvenida
            ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f), ImGuiCond_Always, ImVec2(0.5f, 0.5f));
            ImGui::SetNextWindowSize(ImVec2(600, 350));
            ImGui::Begin("Bienvenida", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings);
            
            ImGui::Spacing(); ImGui::Spacing(); ImGui::Spacing();
            ImGui::SetCursorPosX((600 - ImGui::CalcTextSize("Bienvenido al Sniffer de Redes").x) * 0.5f);
            ImGui::TextColored({0.4f, 0.8f, 1.0f, 1.0f}, "Bienvenido al Sniffer de Redes");
            
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            
            ImGui::Text("Miembros del equipo:");
            ImGui::BulletText("Erich Leonardo Castruita Rodriguez");
            ImGui::BulletText("Diego Joao Sanchez Lopez");
            ImGui::BulletText("Joshua Alejandro Bravo Lopez");
            ImGui::BulletText("Rodrigo Vazquez Zuñiga");
            ImGui::BulletText("Carlos Antonio Villaseñor Garcia");
            
            ImGui::Spacing(); ImGui::Spacing(); ImGui::Spacing();
            ImGui::SetCursorPosX((600 - 200) * 0.5f);
            if (ImGui::Button("Comenzar a Sniffear", ImVec2(200, 50))) {
                show_welcome = false;   //dejamos de mostrar la pantalla de bienvenida
            }
            ImGui::End();
        } else {
            //Main menu bar
            if (ImGui::BeginMainMenuBar()) {
                if (ImGui::BeginMenu("Archivo")) {
                    if (ImGui::MenuItem("Guardar Reporte CSV")) {
                        if (exportarCSV(csv_path)) exportado = true;
                    }
                    ImGui::EndMenu();
                }
                if (ImGui::BeginMenu("Opciones")) {
                    if (ImGui::MenuItem("Configurar Filtros BPF")) {
                        open_filtros_modal = true;
                    }
                    ImGui::EndMenu();
                }
                ImGui::EndMainMenuBar();
            }

            ImGui::SetNextWindowPos({0, ImGui::GetFrameHeight()});
            ImGui::SetNextWindowSize({io.DisplaySize.x, io.DisplaySize.y - ImGui::GetFrameHeight()});
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20, 20));
            ImGui::Begin("##root", nullptr,
                ImGuiWindowFlags_NoDecoration    | ImGuiWindowFlags_NoMove         |
                ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus);

            ImGui::TextUnformatted("Sniffer");
            ImGui::Separator();
            ImGui::Spacing();
            
            if (exportado) {
                ImGui::TextColored({0.3f, 1.0f, 0.3f, 1.0f}, "Reporte guardado exitosamente en %s", csv_path);
                ImGui::Spacing();
            }

            ImGui::Text("1. Selecciona tu conexión a Internet:");
            ImGui::SetNextItemWidth(400);
            if (!iface_descs.empty()) {
                vector<const char*> ptrs;
                for (auto& s : iface_descs) ptrs.push_back(s.c_str());
                if (g_capturando) ImGui::BeginDisabled();
                ImGui::Combo("##iface", &sel_iface, ptrs.data(), (int)ptrs.size());
                if (g_capturando) ImGui::EndDisabled();
            } else {
                ImGui::TextColored({1, 0.4f, 0.4f, 1}, "No se encontraron interfaces.");
            }

            ImGui::Spacing();
            ImGui::Spacing();

            if (!g_capturando) {
                ImGui::PushStyleColor(ImGuiCol_Button,        {0.15f, 0.65f, 0.15f, 1.0f});
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, {0.20f, 0.85f, 0.20f, 1.0f});
                if (ImGui::Button("INICIAR CAPTURA", ImVec2(200, 50)) && !iface_names.empty()) {
                    sel_paquete = -1;
                    cached_idx  = -1;
                    exportado   = false;
                    { lock_guard<mutex> lk(g_mtx); g_meta.clear(); g_raw.clear(); }
                    g_capturando = true;
                    if (hilo_cap.joinable()) hilo_cap.join();
                    hilo_cap = thread(runCapture, iface_names[sel_iface], string(filtro_buf));
                    //creamos un hilo nuevo, ejecutando runCapture mientras q la GUI sigue funcionando
                }
                ImGui::PopStyleColor(2);
            } else {
                ImGui::PushStyleColor(ImGuiCol_Button,        {0.85f, 0.15f, 0.15f, 1.0f});
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, {1.00f, 0.20f, 0.20f, 1.0f});
                if (ImGui::Button("DETENER CAPTURA", ImVec2(200, 50))) {
                    if (g_handle) pcap_breakloop(g_handle); //salir del pcap_loop, terminando runCapture()
                }
                ImGui::PopStyleColor(2);
            }

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            size_t n_paquetes;
            vector<PaqueteMeta> snap;
            { lock_guard<mutex> lk(g_mtx); snap = g_meta; n_paquetes = g_meta.size(); }

            ImGui::Text("Total de conexiones detectadas: %zu", n_paquetes);
            if (g_capturando) {
                ImGui::SameLine();
                ImGui::TextColored({0.3f, 1.0f, 0.3f, 1.0f}, "(Analizando...)");
            }
            ImGui::SameLine(ImGui::GetWindowWidth() - 150);
            ImGui::Checkbox("Auto-Scroll", &auto_scroll);

            ImGui::Spacing();

            ImGui::BeginChild("ListaPaquetes", ImVec2(0, -220), true);
            if (ImGui::BeginTable("TablaPaquetes", 6, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("No.", ImGuiTableColumnFlags_WidthFixed, 40.0f);
                ImGui::TableSetupColumn("Protocolo", ImGuiTableColumnFlags_WidthFixed, 70.0f);
                ImGui::TableSetupColumn("Servicio", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                ImGui::TableSetupColumn("IP Origen");
                ImGui::TableSetupColumn("IP Destino");
                ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 60.0f);
                ImGui::TableHeadersRow();

                for (int i = 0; i < (int)snap.size(); i++) {
                    const auto& m = snap[i];
                    
                    ImVec4 col = colorProtocolo(m.protocolo);
                    ImU32 row_bg_color = ImGui::GetColorU32(ImVec4(col.x, col.y, col.z, 0.15f));
                    ImGui::TableNextRow();
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, row_bg_color);
                    
                    ImGui::TableSetColumnIndex(0);
                    char label[32];
                    snprintf(label, sizeof(label), "%d", i + 1);
                    bool is_selected = (sel_paquete == i);
                    if (ImGui::Selectable(label, is_selected, ImGuiSelectableFlags_SpanAllColumns)) {
                        //al hacer click guarda los detalles de ese paquete 
                        sel_paquete = i;
                        cached_idx = i;
                        cached_meta = m;
                    }

                    ImGui::TableSetColumnIndex(1); ImGui::TextColored(col, "%s", m.protocolo.c_str());
                    ImGui::TableSetColumnIndex(2); ImGui::Text("%s", m.servicio.c_str());
                    ImGui::TableSetColumnIndex(3); ImGui::Text("%s:%d", m.ip_origen.c_str(), m.puerto_origen);
                    ImGui::TableSetColumnIndex(4); ImGui::Text("%s:%d", m.ip_destino.c_str(), m.puerto_destino);
                    ImGui::TableSetColumnIndex(5); ImGui::Text("%zu", m.raw_size);
                }
                
                if (auto_scroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
                    ImGui::SetScrollHereY(1.0f);
                }
                
                ImGui::EndTable();
            }
            if (snap.empty()) {
                ImGui::TextDisabled("Aún no hay actividad. Dale click a Iniciar Monitor...");
            }
            ImGui::EndChild();

            //VISTA DE ARBOL DE DETALLES
            ImGui::BeginChild("DetallesPaquete", ImVec2(0, 0), true);
            ImGui::TextColored({0.4f, 0.8f, 1.0f, 1.0f}, "Análisis Detallado del Paquete Seleccionado");
            ImGui::Separator();
            ImGui::Spacing();
            
            if (sel_paquete >= 0 && sel_paquete == cached_idx) {
                if (ImGui::TreeNodeEx("Capa de Enlace (Ethernet)", ImGuiTreeNodeFlags_DefaultOpen)) {
                    ImGui::Text("Tamaño total capturado en la trama: %zu bytes", cached_meta.raw_size);
                    ImGui::TreePop();
                }
                if (ImGui::TreeNodeEx("Capa de Red (IPv4)", ImGuiTreeNodeFlags_DefaultOpen)) {
                    ImGui::Text("Dirección IP de Origen: %s", cached_meta.ip_origen.c_str());
                    ImGui::Text("Dirección IP de Destino: %s", cached_meta.ip_destino.c_str());
                    ImGui::TreePop();
                }
                if (ImGui::TreeNodeEx("Capa de Transporte", ImGuiTreeNodeFlags_DefaultOpen)) {
                    ImVec4 col = colorProtocolo(cached_meta.protocolo);
                    ImGui::Text("Protocolo: "); ImGui::SameLine(); ImGui::TextColored(col, "%s", cached_meta.protocolo.c_str());
                    ImGui::Text("Puerto de Origen: %d", cached_meta.puerto_origen);
                    ImGui::Text("Puerto de Destino: %d", cached_meta.puerto_destino);
                    
                    if (cached_meta.servicio != "---") {
                        ImGui::TextColored({0.3f, 1.0f, 0.3f, 1.0f}, "Servicio de aplicación detectado: %s", cached_meta.servicio.c_str());
                    }
                    ImGui::TreePop();
                }
                
                ImGui::Spacing();
                if (ImGui::Button("Ver datos crudos (Hexadecimal)", ImVec2(250, 30))) {
                    lock_guard<mutex> lk(g_mtx);
                    if (sel_paquete < (int)g_raw.size()) hex_raw_data = g_raw[sel_paquete];
                    else hex_raw_data.clear();
                    open_hex_modal = true;
                }
            } else {
                ImGui::TextDisabled("\nSelecciona un paquete en la tabla de arriba para ver sus detalles aquí.");
            }
            ImGui::EndChild();

            if (open_hex_modal) {
                ImGui::OpenPopup("Vista Hexadecimal");
                open_hex_modal = false;
            }

            if (ImGui::BeginPopupModal("Vista Hexadecimal", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
                renderHex(hex_raw_data);    //Al presionar Vista Hexadecimal podemos ver los datos en crudo
                ImGui::Spacing();
                if (ImGui::Button("Cerrar", ImVec2(120, 0))) {
                    ImGui::CloseCurrentPopup();
                }
                ImGui::EndPopup();
            }

            if (open_filtros_modal) {
                ImGui::OpenPopup("Configurar Filtros");
                open_filtros_modal = false;
            }

            if (ImGui::BeginPopupModal("Configurar Filtros", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
                //nos permite escribir los filtros
                ImGui::Text("Filtro BPF Avanzado:");
                ImGui::InputText("##filtro", filtro_buf, sizeof(filtro_buf));
                ImGui::TextDisabled("Ejemplos: 'tcp port 443' o 'udp port 53'\nDeja en blanco para capturar todo.");
                ImGui::Spacing();
                if (ImGui::Button("Aceptar", ImVec2(120, 0))) {
                    ImGui::CloseCurrentPopup();
                }
                ImGui::EndPopup();
            }

            ImGui::PopStyleVar();
            ImGui::End();
        }

        //Renderizado OpenGL
        ImGui::Render();    //generar interfaz
        int fb_w, fb_h;
        glfwGetFramebufferSize(window, &fb_w, &fb_h);
        glViewport(0, 0, fb_w, fb_h);   //definir area de dibujo
        glClearColor(0.10f, 0.10f, 0.12f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);   //limpiar pantalla
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData()); //dibuja todo
        glfwSwapBuffers(window);    //mostrar el frame
    }

    //Limpieza al cerrar
    if (g_capturando && g_handle) pcap_breakloop(g_handle); //Detiene captura
    if (hilo_cap.joinable()) hilo_cap.join();   //Espera a que termine el hilo evitando crashes, cerrar hilos, etc.
    
    //Destruimos todo correctamente
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}