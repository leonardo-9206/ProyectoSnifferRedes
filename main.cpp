// Proyecto Final: Packet Sniffer
// Equipo: Erich Leonardo, Diego Joao, Joshua Alejandro, Rodrigo Vazquez, Carlos Antonio
// Descripcion: Sniffer desarrollado en C++ utilizando Npcap para la captura de paquetes 
//              y Dear ImGui para la interfaz grafica.
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

// Estructuras para las cabeceras de los protocolos de red (importante quitar el padding con pragma pack)
#pragma pack(push, 1)
struct ip_address { u_char b1, b2, b3, b4; };

struct ip_header {
    u_char  ver_ihl, tos;
    u_short tlen, id, flags_fo;
    u_char  ttl, proto;
    u_short crc;
    ip_address saddr, daddr;
};

struct udp_header { u_short sport, dport, len, crc; };

struct tcp_header {
    u_short sport, dport;
    u_int   seq, ack;
    u_char  data_offset, flags;
    u_short window, crc, urp;
};
#pragma pack(pop)

// Estructuras de datos para manejar la informacion capturada

// Metadatos livianos del paquete (para mostrarlos rapido en la tabla sin saturar la memoria)
struct PaqueteMeta {
    string ip_origen, ip_destino, protocolo, servicio;
    int    puerto_origen  = 0;
    int    puerto_destino = 0;
    size_t raw_size       = 0;
};

// Variables globales (usamos mutex porque la interfaz grafica y el sniffer corren al mismo tiempo)
static vector<PaqueteMeta>          g_meta;   // metadatos para la tabla
static vector<vector<uint8_t>>      g_raw;    // bytes crudos por paquete
static mutex                        g_mtx;
static atomic<bool>                 g_capturando{false};
static pcap_t*                      g_handle = nullptr;

// ─── Helpers ─────────────────────────────────────────────────────────────────
static string ipStr(ip_address ip) {
    char buf[20];
    snprintf(buf, sizeof(buf), "%d.%d.%d.%d", ip.b1, ip.b2, ip.b3, ip.b4);
    return buf;
}

static const char* getServicio(int puerto) {
    switch (puerto) {
        case 20:   return "FTP-Data";
        case 21:   return "FTP";
        case 22:   return "SSH";
        case 23:   return "Telnet";
        case 25:   return "SMTP";
        case 53:   return "DNS";
        case 67:   return "DHCP-S";
        case 68:   return "DHCP-C";
        case 80:   return "HTTP";
        case 110:  return "POP3";
        case 123:  return "NTP";
        case 143:  return "IMAP";
        case 443:  return "HTTPS";
        case 445:  return "SMB";
        case 587:  return "SMTP-S";
        case 993:  return "IMAPS";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 5432: return "Postgres";
        default:   return "---";
    }
}

// Callback de captura: Esta funcion la manda a llamar npcap automaticamente cada que atrapa un paquete
void packet_handler(u_char*, const struct pcap_pkthdr* hdr, const u_char* pkt) {
    if (hdr->caplen < 14) return;

    auto* ih = (ip_header*)(pkt + 14);
    if ((ih->ver_ihl >> 4) != 4) return; // solo IPv4

    PaqueteMeta meta;
    meta.ip_origen  = ipStr(ih->saddr);
    meta.ip_destino = ipStr(ih->daddr);
    meta.raw_size   = hdr->caplen;

    u_int ihl = (ih->ver_ihl & 0xf) * 4;

    if (ih->proto == 6 && hdr->caplen >= 14u + ihl + 20u) {
        meta.protocolo = "TCP";
        auto* th = (tcp_header*)((u_char*)ih + ihl);
        meta.puerto_origen  = ntohs(th->sport);
        meta.puerto_destino = ntohs(th->dport);
    } else if (ih->proto == 17 && hdr->caplen >= 14u + ihl + 8u) {
        meta.protocolo = "UDP";
        auto* uh = (udp_header*)((u_char*)ih + ihl);
        meta.puerto_origen  = ntohs(uh->sport);
        meta.puerto_destino = ntohs(uh->dport);
    } else if (ih->proto == 1) {
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
    if (string(svc) == "---") svc = getServicio(meta.puerto_origen);
    meta.servicio = svc;

    vector<uint8_t> raw(pkt, pkt + hdr->caplen);

    lock_guard<mutex> lk(g_mtx);
    g_meta.push_back(move(meta));
    g_raw.push_back(move(raw));
}

// Funcion del hilo secundario: abre la tarjeta de red y empieza el ciclo de captura (pcap_loop)
void runCapture(string iface, string filtro) {
    char errbuf[PCAP_ERRBUF_SIZE];
    g_handle = pcap_open_live(iface.c_str(), 65536, 1, 1000, errbuf);
    if (!g_handle) {
        g_capturando = false;
        return;
    }

    if (!filtro.empty()) {
        struct bpf_program fp;
        if (pcap_compile(g_handle, &fp, filtro.c_str(), 1, PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_setfilter(g_handle, &fp);
            pcap_freecode(&fp);
        }
    }

    pcap_loop(g_handle, 0, packet_handler, nullptr);
    pcap_close(g_handle);
    g_handle     = nullptr;
    g_capturando = false;
}

// Funcion para formatear los bytes crudos a una vista hexadecimal clasica
static void renderHex(const vector<uint8_t>& data) {
    if (data.empty()) { ImGui::TextDisabled("(sin datos)"); return; }

    static char buf[1024 * 128];
    int pos = 0;
    const int cap = (int)sizeof(buf) - 128;

    for (size_t i = 0; i < data.size() && pos < cap; i += 16) {
        pos += snprintf(buf + pos, cap - pos, "%04X  ", (unsigned)i);

        for (int j = 0; j < 16; j++) {
            if (i + j < data.size())
                pos += snprintf(buf + pos, cap - pos, "%02X ", data[i + j]);
            else
                pos += snprintf(buf + pos, cap - pos, "   ");
            if (j == 7) pos += snprintf(buf + pos, cap - pos, " ");
        }

        pos += snprintf(buf + pos, cap - pos, "  ");
        for (int j = 0; j < 16 && i + j < data.size(); j++) {
            uint8_t c = data[i + j];
            buf[pos++] = (c >= 32 && c < 127) ? (char)c : '.';
        }
        buf[pos++] = '\n';
    }
    buf[pos] = '\0';

    ImGui::InputTextMultiline("##hex", buf, sizeof(buf),
        ImVec2(800, 400), ImGuiInputTextFlags_ReadOnly);
}

// Funcion para guardar los datos de la tabla en un archivo Excel/CSV
static bool exportarCSV(const char* archivo) {
    ofstream f(archivo);
    if (!f) return false;
    f << "Protocolo,Servicio,IP Origen,Puerto Origen,IP Destino,Puerto Destino,Bytes\n";
    lock_guard<mutex> lk(g_mtx);
    for (size_t i = 0; i < g_meta.size(); i++) {
        const auto& m = g_meta[i];
        f << m.protocolo << "," << m.servicio << ","
          << m.ip_origen << "," << m.puerto_origen << ","
          << m.ip_destino << "," << m.puerto_destino << ","
          << m.raw_size  << "\n";
    }
    return true;
}

// Funcion auxiliar para darle colores bonitos a cada protocolo en la tabla
static ImVec4 colorProtocolo(const string& proto) {
    if (proto == "TCP")  return {0.40f, 0.80f, 1.00f, 1.0f};
    if (proto == "UDP")  return {0.50f, 1.00f, 0.50f, 1.0f};
    if (proto == "ICMP") return {1.00f, 0.85f, 0.30f, 1.0f};
    if (proto == "IGMP") return {0.90f, 0.50f, 0.80f, 1.0f};
    if (proto == "IPv6") return {0.70f, 0.70f, 0.90f, 1.0f};
    if (proto == "OSPF") return {0.80f, 0.60f, 0.20f, 1.0f};
    return                      {0.80f, 0.80f, 0.80f, 1.0f};
}

// Funcion principal que levanta la interfaz grafica y controla la aplicacion
int main() {
    // ── GLFW ──
    if (!glfwInit()) return 1;
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);

    GLFWwindow* window = glfwCreateWindow(1400, 850, "Packet Sniffer - Redes", nullptr, nullptr);
    if (!window) { glfwTerminate(); return 1; }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    // ── ImGui ──
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    ImGui::StyleColorsDark();

    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding   = 4.0f;
    style.FrameRounding    = 3.0f;
    style.ScrollbarRounding = 3.0f;

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 330");

    // ── Enumerar interfaces de red ──
    pcap_if_t* alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_findalldevs(&alldevs, errbuf);

    vector<string> iface_names, iface_descs;
    for (pcap_if_t* d = alldevs; d; d = d->next) {
        iface_names.push_back(d->name);
        iface_descs.push_back(d->description ? d->description : d->name);
    }
    pcap_freealldevs(alldevs);

    // ── Estado de la UI ──
    int  sel_iface   = 0;
    int  sel_paquete = -1;
    char filtro_buf[256] = "";
    char csv_path[256]   = "captura_trafico.csv";

    bool show_welcome = true;
    bool auto_scroll  = true;

    // Caché del paquete seleccionado (evita lockear cada frame)
    PaqueteMeta     cached_meta;
    vector<uint8_t> cached_raw;
    int             cached_idx = -1;

    thread hilo_cap;
    bool   exportado   = false;

    // Estado para modal Hex
    bool open_hex_modal = false;
    vector<uint8_t> hex_raw_data;

    // Estado para modal Filtros
    bool open_filtros_modal = false;

    // ── Render loop ───────────────────────────────────────────────────────────
    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        if (show_welcome) {
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
                show_welcome = false;
            }
            ImGui::End();
        } else {
            // Main menu bar
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
                }
                ImGui::PopStyleColor(2);
            } else {
                ImGui::PushStyleColor(ImGuiCol_Button,        {0.85f, 0.15f, 0.15f, 1.0f});
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, {1.00f, 0.20f, 0.20f, 1.0f});
                if (ImGui::Button("DETENER CAPTURA", ImVec2(200, 50))) {
                    if (g_handle) pcap_breakloop(g_handle);
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

            // AREA 2: VISTA DE ARBOL DE DETALLES
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
                renderHex(hex_raw_data);
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

        // ── Renderizado OpenGL ────────────────────────────────────────────────
        ImGui::Render();
        int fb_w, fb_h;
        glfwGetFramebufferSize(window, &fb_w, &fb_h);
        glViewport(0, 0, fb_w, fb_h);
        glClearColor(0.10f, 0.10f, 0.12f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    // ── Limpieza al cerrar ────────────────────────────────────────────────────
    if (g_capturando && g_handle) pcap_breakloop(g_handle);
    if (hilo_cap.joinable()) hilo_cap.join();

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}
